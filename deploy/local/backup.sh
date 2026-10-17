#!/usr/bin/env bash
# backup.sh — the backup and restore drill, on a throwaway kind cluster that is
# deleted afterwards whether the drill passed or failed.
#
#   1. edge-datastores (bundled) with its backup switched on, pointed at a MinIO
#      bucket; the edge database seeded with a gateway, two routes and their
#      clusters, the issuer database and a stand-in for Lens's own database
#      (no chart here installs Lens) seeded with rows. A control plane reads the
#      edge database and publishes its config; its xDS version is a pure function
#      of the config hash (internal/xds/reconciler.go versionFromHash).
#   2. BACKUP   a Job made from the chart's backup CronJob dumps all three
#               databases to MinIO; the bucket then holds the three dumps, their
#               MANIFEST and LATEST naming them.
#   3. LOSS     the whole namespace is deleted — release, volumes, connection
#               Secret, passwords — and the chart installed again from scratch.
#               The databases are empty and the control plane publishes a
#               different config hash, so the check below can fail.
#   4. RESTORE  a Job made from the chart's restore CronJob checks every dump
#               against the MANIFEST and restores each database. The running
#               control plane goes back to the config hash it published before
#               the loss, a control plane started cold on the restored database
#               publishes it too, and every table in all three databases holds
#               exactly what it held at the backup.
#
#   make kind-backup                    # == deploy/local/backup.sh
#   KEEP_CLUSTER=1 make kind-backup     # leave the cluster up afterwards
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-backup}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq

CHART="$REPO_ROOT/deploy/helm/edge-datastores"
RELEASE=edge-datastores
NS=edge-data
STORE_NS=backup-store
BUCKET=edge-backups
S3_USER=drill-access-key
S3_PASS=drill-secret-key-0123456789
# The S3 client is the image the chart's backup runs; MinIO is a maintained build
# of its own source.
S3_IMAGE="$(sed -n '/^    s3:$/,/tag:/{s/^ *repository: //p;}' "$CHART/values.yaml"):$(sed -n '/^    s3:$/,/tag:/{s/^ *tag: "\(.*\)"$/\1/p;}' "$CHART/values.yaml")"
MINIO_IMAGE="${MINIO_IMAGE:-pgsty/minio:RELEASE.2026-08-04T00-00-00Z@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372}"
DATABASES=(edge issuer lens)
DIGESTS="$(mktemp -d)"   # <db> -> its digest at the backup

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (kind delete cluster --name $CLUSTER_NAME) or pick another CLUSTER_NAME"
fi

started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  rm -rf "$DIGESTS"
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "FAILED (exit $rc) — cluster state before teardown"
    k get pods,pvc,jobs -A -o wide 2>/dev/null || true
    k -n "$NS" logs -l app.kubernetes.io/component=backup --all-containers --tail=50 2>/dev/null || true
    k -n "$NS" logs -l app.kubernetes.io/component=restore --all-containers --tail=50 2>/dev/null || true
    k -n "$NS" logs deploy/edge-control-plane --tail=30 2>/dev/null || true
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up; delete it with: kind delete cluster --name $CLUSTER_NAME"
  else
    kind delete cluster --name "$CLUSTER_NAME" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
  fi
  if [ "$rc" = 0 ]; then
    ok "kind-backup PASSED in $(( ($(date +%s) - started) / 60 )) min — restored from MinIO, same config hash, cluster removed"
  else
    printf '%s  X kind-backup FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT

# ---- helpers -----------------------------------------------------------------
pg_pod() { k -n "$NS" get pod -l app.kubernetes.io/name=postgres -o jsonpath='{.items[0].metadata.name}'; }
psql_db() { k -n "$NS" exec -i "$(pg_pod)" -- psql -U edge -d "$1" -v ON_ERROR_STOP=1 -tA "${@:2}"; }

# db_digest <db> — "<tables> tables, <rows> rows, <md5>": an md5 over every
# public table's name and the md5 of its rows in a fixed order.
db_digest() {
  psql_db "$1" <<'SQL' | tr -d '\r'
WITH t AS (
  SELECT table_name AS name,
         (xpath('/row/h/text()', query_to_xml(format(
           'SELECT md5(coalesce(string_agg(x::text, chr(10) ORDER BY x::text), '''')) || '':'' || count(*) AS h FROM public.%I x',
           table_name), false, true, '')))[1]::text AS h
  FROM information_schema.tables
  WHERE table_schema = 'public' AND table_type = 'BASE TABLE')
SELECT count(*) || ' tables, ' || coalesce(sum(split_part(h, ':', 2)::bigint), 0) || ' rows, '
       || md5(coalesce(string_agg(name || '=' || h, ',' ORDER BY name), ''))
FROM t;
SQL
}

# snapshot_versions <pod> <min-listeners> — every xDS version the control plane
# has published with at least that many listeners, in order.
snapshot_versions() {
  k -n "$NS" logs "$1" 2>/dev/null \
    | jq -Rr --argjson n "$2" 'fromjson? | select(.msg == "snapshot pushed" and .listeners >= $n) | .version'
}

# wait_version <pod> <min-listeners> [want] — the last version published with at
# least that many listeners, or wait until it is <want>. Echoes it.
wait_version() {
  local src="$1" n="$2" want="${3:-}" v="" _
  for _ in $(seq 60); do
    v="$(snapshot_versions "$src" "$n" | tail -1)"
    if [ -n "$v" ] && { [ -z "$want" ] || [ "$v" = "$want" ]; }; then echo "$v"; return 0; fi
    sleep 2
  done
  echo "$v"
  return 1
}

# run_job <cronjob> <job> — a Job made from the CronJob, waited for; prints its log.
run_job() {
  k -n "$NS" create job --from="cronjob/$1" "$2" >/dev/null
  local s="" _
  for _ in $(seq 90); do
    s="$(k -n "$NS" get job "$2" -o json | jq -r '[.status.conditions[]? | select(.status == "True") | .type] | join(",")')"
    case "$s" in *Complete*|*Failed*) break ;; esac
    sleep 2
  done
  k -n "$NS" logs "job/$2" --all-containers --prefix | sed 's/^/    /'
  case "$s" in *Complete*) ;; *) die "job $2 did not complete (conditions: ${s:-none})" ;; esac
}

s3() { k -n "$STORE_NS" exec deploy/s3-client -- aws "$@"; }

install_chart() {
  section "helm install $RELEASE -> ns/$NS (bundled, backup to s3://$BUCKET on MinIO)"
  k create namespace "$NS" >/dev/null
  # The bucket's keys live outside the cluster; an operator applies them again.
  k -n "$NS" create secret generic edge-backup-s3 \
    --from-literal=AWS_ACCESS_KEY_ID="$S3_USER" --from-literal=AWS_SECRET_ACCESS_KEY="$S3_PASS" >/dev/null
  h install "$RELEASE" "$CHART" -n "$NS" --wait --timeout 10m \
    --set migrate.image.repository=edge-migrate --set "migrate.image.tag=$IMAGE_TAG" --set migrate.image.pullPolicy=Never \
    --set 'postgres.extraDatabases={issuer,lens}' \
    --set backup.enabled=true \
    --set "backup.s3.endpoint=http://minio.$STORE_NS.svc.cluster.local:9000" \
    --set "backup.s3.bucket=$BUCKET" \
    --set backup.s3.existingSecret=edge-backup-s3 \
    --set 'backup.extraDatabases[0].name=lens' \
    --set 'backup.extraDatabases[0].secretName=lens-database' \
    --set 'backup.extraDatabases[0].key=DATABASE_URL'
  wait_rollout "statefulset/$RELEASE-postgres" "$NS" 120s
  # The stand-in Lens database's own connection Secret, from this install's password.
  local pw; pw="$(k -n "$NS" get secret "$RELEASE" -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"
  k -n "$NS" create secret generic lens-database \
    --from-literal=DATABASE_URL="postgres://edge:$pw@$RELEASE-postgres.$NS.svc.cluster.local:5432/lens?sslmode=disable" >/dev/null
  ok "edge-datastores installed with backup on; databases: ${DATABASES[*]}"
}

start_control_plane() {
  k -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: edge-control-plane, labels: { app: edge-control-plane } }
spec:
  selector: { matchLabels: { app: edge-control-plane } }
  template:
    metadata: { labels: { app: edge-control-plane } }
    spec:
      securityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: { type: RuntimeDefault } }
      containers:
        - name: server
          image: edge-control-plane:$IMAGE_TAG
          imagePullPolicy: Never
          envFrom: [{ secretRef: { name: $RELEASE } }]
          # No Envoy connects here (backup only), so xDS runs in its explicit dev mode.
          env: [{ name: XDS_RECONCILE_INTERVAL_MS, value: "2000" }, { name: XDS_DEV_INSECURE, value: "true" }]
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
EOF
  wait_rollout deploy/edge-control-plane "$NS" 180s
}

# cp_pod — the running control-plane pod that is not on its way out.
cp_pod() {
  k -n "$NS" get pod -l app=edge-control-plane -o json \
    | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")][0].metadata.name // empty'
}

# ---- cluster, images, MinIO --------------------------------------------------
section "kind cluster '$CLUSTER_NAME'"
kind create cluster --name "$CLUSTER_NAME" --wait 120s
section "build the migrate and control-plane images from the working tree"
docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target migrate -t "edge-migrate:$IMAGE_TAG" "$REPO_ROOT"
docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target server -t "edge-control-plane:$IMAGE_TAG" "$REPO_ROOT"
kind load docker-image --name "$CLUSTER_NAME" "edge-migrate:$IMAGE_TAG" "edge-control-plane:$IMAGE_TAG"

section "MinIO in ns/$STORE_NS, and the bucket $BUCKET"
k create namespace "$STORE_NS" >/dev/null
k -n "$STORE_NS" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: minio, labels: { app: minio } }
spec:
  selector: { matchLabels: { app: minio } }
  template:
    metadata: { labels: { app: minio } }
    spec:
      containers:
        - name: minio
          image: $MINIO_IMAGE
          args: ["server", "/data"]
          env:
            - { name: MINIO_ROOT_USER, value: $S3_USER }
            - { name: MINIO_ROOT_PASSWORD, value: $S3_PASS }
          ports: [{ containerPort: 9000 }]
          readinessProbe: { httpGet: { path: /minio/health/ready, port: 9000 }, periodSeconds: 2 }
          volumeMounts: [{ name: data, mountPath: /data }]
      volumes: [{ name: data, emptyDir: {} }]
---
apiVersion: v1
kind: Service
metadata: { name: minio }
spec:
  selector: { app: minio }
  ports: [{ port: 9000 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: s3-client, labels: { app: s3-client } }
spec:
  selector: { matchLabels: { app: s3-client } }
  template:
    metadata: { labels: { app: s3-client } }
    spec:
      containers:
        - name: aws
          image: $S3_IMAGE
          # Path-style URLs, as the chart's own backup uses (backup.s3.forcePathStyle).
          command: ["sh", "-c", "printf '[default]\\ns3 =\\n  addressing_style = path\\n' >/tmp/aws-config && exec sleep infinity"]
          env:
            - { name: AWS_CONFIG_FILE, value: /tmp/aws-config }
            - { name: AWS_ACCESS_KEY_ID, value: $S3_USER }
            - { name: AWS_SECRET_ACCESS_KEY, value: $S3_PASS }
            - { name: AWS_DEFAULT_REGION, value: us-east-1 }
            - { name: AWS_ENDPOINT_URL, value: "http://minio:9000" }
EOF
wait_rollout deploy/minio "$STORE_NS" 240s
wait_rollout deploy/s3-client "$STORE_NS" 240s
s3 s3 mb "s3://$BUCKET" >/dev/null
ok "MinIO up; s3://$BUCKET created"

# ---- 1. a working install with config --------------------------------------
install_chart
section "seed: a gateway, two routes and their clusters (edge); rows in issuer and lens"
psql_db edge <<'SQL' >/dev/null
BEGIN;
INSERT INTO gateways (id, name, port, protocol, node_selector) VALUES ('drill-gw','drill-gw',443,'HTTP','{}'::jsonb);
INSERT INTO clusters (id, name) VALUES ('tenant-a','tenant-a'), ('tenant-b','tenant-b');
INSERT INTO endpoints (id, cluster_id, address, port, weight)
  VALUES ('tenant-a-0','tenant-a','10.96.10.10',5678,1), ('tenant-b-0','tenant-b','10.96.10.11',5678,1);
INSERT INTO routes (id, name, gateway_id, hosts, path_prefix, cluster_name, timeout_seconds, auth_policy)
  VALUES ('tenant-a','tenant-a','drill-gw',ARRAY['tenant-a.local'],'/','tenant-a',30,'none'),
         ('tenant-b','tenant-b','drill-gw',ARRAY['tenant-b.local'],'/','tenant-b',30,'none');
COMMIT;
SQL
for db in issuer lens; do
  psql_db "$db" -c "CREATE TABLE drill_rows (id bigint PRIMARY KEY, note text NOT NULL, at timestamptz NOT NULL DEFAULT now());
    INSERT INTO drill_rows (id, note) SELECT g, '$db row ' || g FROM generate_series(1, 250) g;" >/dev/null
done
start_control_plane
V_BEFORE="$(wait_version "$(cp_pod)" 1)" || die "the control plane never published a config with a listener"
ok "control plane publishes xDS version $V_BEFORE (the config hash) for 1 gateway, 2 routes"
for db in "${DATABASES[@]}"; do db_digest "$db" >"$DIGESTS/$db"; log "$db: $(cat "$DIGESTS/$db")"; done

# ---- 2. backup ---------------------------------------------------------------
section "BACKUP — a Job from cronjob/$RELEASE-backup"
run_job "$RELEASE-backup" drill-backup
STAMP="$(s3 s3 cp "s3://$BUCKET/edge/LATEST" - | tr -d '[:space:]')"
[ -n "$STAMP" ] || die "s3://$BUCKET/edge/LATEST is empty after the backup"
LISTING="$(s3 s3 ls "s3://$BUCKET/edge/$STAMP/")"
printf '%s\n' "$LISTING" | sed 's/^/    /'
for f in edge.dump issuer.dump lens.dump MANIFEST; do
  has "$LISTING" " $f" || die "s3://$BUCKET/edge/$STAMP/ has no $f"
done
ok "MinIO holds backup $STAMP: edge, issuer and lens dumps and their MANIFEST; LATEST names it"

# ---- 3. loss -----------------------------------------------------------------
section "LOSS — delete ns/$NS (release, volumes, connection Secret) and install again from scratch"
k delete namespace "$NS" --wait --timeout=180s
for _ in $(seq 60); do [ -z "$(k get pv -o name)" ] && break; sleep 2; done
[ -z "$(k get pv -o name)" ] || die "the deleted namespace's volumes are still there — the loss is not total"
install_chart
start_control_plane
[ "$(psql_db edge -c 'SELECT count(*) FROM gateways' | tr -d '[:space:]')" = 0 ] || die "the new edge database is not empty"
for db in "${DATABASES[@]}"; do
  d="$(db_digest "$db")"
  [ "$d" != "$(cat "$DIGESTS/$db")" ] || die "$db already matches its backup before any restore — the comparison below would prove nothing"
done
# A control plane on an empty database publishes no listener: the version it
# publishes for the empty config (first snapshot) differs from V_BEFORE.
V_EMPTY="$(wait_version "$(cp_pod)" 0)" && [ "$V_EMPTY" != "$V_BEFORE" ] \
  || die "after the loss the control plane publishes '${V_EMPTY:-nothing}', not a config other than $V_BEFORE"
ok "all three databases empty; the control plane publishes $V_EMPTY, not $V_BEFORE"

# ---- 4. restore --------------------------------------------------------------
section "RESTORE — a Job from cronjob/$RELEASE-restore (restoreFrom: latest)"
run_job "$RELEASE-restore" drill-restore
LIVE="$(cp_pod)"
V_LIVE="$(wait_version "$LIVE" 1 "$V_BEFORE")" \
  || die "the running control plane publishes ${V_LIVE:-nothing} after the restore, not $V_BEFORE"
ok "the running control plane is back on config hash $V_LIVE"
k -n "$NS" rollout restart deploy/edge-control-plane >/dev/null
wait_rollout deploy/edge-control-plane "$NS" 180s
for _ in $(seq 30); do [ "$(cp_pod)" != "$LIVE" ] && break; sleep 2; done
COLD="$(cp_pod)"
[ "$COLD" != "$LIVE" ] || die "the control plane did not restart"
V_COLD="$(wait_version "$COLD" 1)" || die "the restarted control plane published no config"
[ "$V_COLD" = "$V_BEFORE" ] || die "a control plane started on the restored database publishes $V_COLD, not $V_BEFORE"
ok "a control plane started cold on the restored database publishes $V_COLD — the config hash from before the loss"
for db in "${DATABASES[@]}"; do
  d="$(db_digest "$db")"
  [ "$d" = "$(cat "$DIGESTS/$db")" ] || die "$db after the restore is '$d', at the backup it was '$(cat "$DIGESTS/$db")'"
  ok "$db: $d — every table as it was at the backup"
done
