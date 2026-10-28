#!/usr/bin/env bash
# datastores.sh — the edge-datastores chart in both of its modes, on a throwaway
# kind cluster that is deleted afterwards whether the run passed or failed.
#
#   bundled   the chart runs Postgres, Redis and NATS itself: all three reach
#             Ready, every migration is recorded in the edge database, and a pod
#             that knows only the connection Secret reaches all three — and so
#             do the chart's own `helm test` pods. An upgrade keeps the generated
#             credentials and the pod still gets in.
#   external  the same chart with all three switched off and pointed at
#             datastores it did not create: it runs no datastore of its own, the
#             schema lands in the external Postgres (empty before the install),
#             and the same pod reaches all three through the Secret.
#
#   make kind-datastores                    # == deploy/local/datastores.sh
#   KEEP_CLUSTER=1 make kind-datastores     # leave the cluster up afterwards
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-datastores}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq

CHART="$REPO_ROOT/deploy/helm/edge-datastores"
RELEASE=edge-datastores
BUNDLED_NS=edge-data
EXTERNAL_NS=edge-data-ext
SECRET=edge-datastores
EXT_REDIS_PASSWORD=external-redis-pass

# The client images are the ones the chart runs, read from its subcharts.
chart_image() { echo "$1:$(sed -n 's/^  tag: "\(.*\)"$/\1/p' "$CHART/charts/$1/values.yaml")"; }
PG_IMAGE="$(chart_image postgres)"
REDIS_IMAGE="$(chart_image redis)"

# Every migration file cmd/migrate embeds — all must be recorded.
MIGRATIONS="$(find "$REPO_ROOT/migrations" "$REPO_ROOT/osb/migrations" -name '*.sql' | wc -l | tr -d ' ')"

MIGRATE_SET=(--set migrate.image.repository=edge-migrate
             --set "migrate.image.tag=$IMAGE_TAG"
             --set migrate.image.pullPolicy=Never)
# NetworkPolicies are on by default: client_check's pod is admitted the way a
# customer admits their own service, through networkPolicy.extraIngress.
CLIENT_SET=(--set-json 'networkPolicy.extraIngress=[{"from":[{"podSelector":{"matchLabels":{"role":"datastore-client"}}}]}]')

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (kind delete cluster --name $CLUSTER_NAME) or pick another CLUSTER_NAME"
fi

started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "FAILED (exit $rc) — cluster state before teardown"
    k get pods,pvc,jobs -A -o wide 2>/dev/null || true
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up; delete it with: kind delete cluster --name $CLUSTER_NAME"
  else
    kind delete cluster --name "$CLUSTER_NAME" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
  fi
  if [ "$rc" = 0 ]; then
    ok "kind-datastores PASSED in $(( ($(date +%s) - started) / 60 )) min — bundled and external both Ready and migrated, cluster removed"
  else
    printf '%s  X kind-datastores FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT

# psql_in <ns> <deploy|sts selector> <user> <db> <sql> — run SQL inside a Postgres pod.
psql_in() {
  local pod
  pod="$(k -n "$1" get pod -l "$2" -o jsonpath='{.items[0].metadata.name}')"
  k -n "$1" exec "$pod" -- psql -U "$3" -d "$4" -tAc "$5" | tr -d '[:space:]'
}

# assert_migrated <ns> <selector> <user> — every migration recorded, core tables present.
assert_migrated() {
  local n core
  n="$(psql_in "$1" "$2" "$3" edge "select count(*) from schema_migrations")"
  [ "$n" = "$MIGRATIONS" ] || die "schema_migrations holds $n row(s), expected all $MIGRATIONS migration files"
  core="$(psql_in "$1" "$2" "$3" edge "select count(*) from information_schema.tables where table_schema='public' and table_name in ('gateways','routes','clusters','endpoints','services')")"
  [ "$core" = 5 ] || die "core tables missing ($core/5 of gateways, routes, clusters, endpoints, services)"
  ok "all $MIGRATIONS migrations recorded; control-plane and OSB tables present"
}

# client_check <ns> — a pod given ONLY the connection Secret reaches Postgres (the
# edge and issuer databases), Redis (with its password) and NATS (with its token).
client_check() {
  local ns="$1" pod="datastore-client-$RANDOM"
  k -n "$ns" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: { name: $pod, labels: { role: datastore-client } }
spec:
  restartPolicy: Never
  containers:
    - name: postgres
      image: $PG_IMAGE
      envFrom: [{ secretRef: { name: $SECRET } }]
      command: ["sh", "-c"]
      args:
        - |
          set -e
          n=\$(psql "\$POSTGRES_DSN" -tAc "select count(*) from schema_migrations")
          echo "edge database: \$n migrations"
          psql "\$ISSUER_DATABASE_URL" -tAc "select 'issuer database: ' || current_database()"
    - name: redis
      image: $REDIS_IMAGE
      envFrom: [{ secretRef: { name: $SECRET } }]
      command: ["sh", "-c"]
      args:
        - |
          r=\$(REDISCLI_AUTH="\$REDIS_PASSWORD" redis-cli -h "\${REDIS_ADDR%:*}" -p "\${REDIS_ADDR##*:}" ping)
          echo "redis: \$r"; [ "\$r" = PONG ]
    - name: nats
      image: $BUSYBOX_IMAGE
      envFrom: [{ secretRef: { name: $SECRET } }]
      command: ["sh", "-c"]
      args:
        - |
          u=\${NATS_URL#nats://}; tok=""
          case "\$u" in *@*) tok=\${u%%@*}; u=\${u#*@} ;; esac
          r=\$(printf 'CONNECT {"verbose":false,"auth_token":"%s"}\r\nPING\r\n' "\$tok" | nc -w 3 "\${u%%:*}" "\${u##*:}")
          if echo "\$r" | grep -q PONG; then echo "nats: PONG"; else echo "nats: \$r"; exit 1; fi
EOF
  local phase="" _
  for _ in $(seq 90); do
    phase="$(k -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}')"
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 2
  done
  if [ "$phase" != Succeeded ]; then
    local c
    for c in postgres redis nats; do echo "  [$c]"; k -n "$ns" logs "$pod" -c "$c" 2>&1 | sed 's/^/    /'; done
    die "a client holding only the '$SECRET' Secret in $ns could not reach every datastore"
  fi
  local c
  for c in postgres redis nats; do k -n "$ns" logs "$pod" -c "$c" | sed 's/^/    /'; done
  k -n "$ns" delete pod "$pod" --wait=false >/dev/null
  ok "a client holding only the connection Secret reached Postgres, Redis and NATS"
}

release_status() { h status "$RELEASE" -n "$1" -o json | jq -r .info.status; }

# ---- cluster + the migrate image ---------------------------------------------
section "kind cluster '$CLUSTER_NAME'"
kind create cluster --name "$CLUSTER_NAME" --wait 120s
section "build the migrate image from the working tree (edge-migrate:$IMAGE_TAG)"
docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target migrate -t "edge-migrate:$IMAGE_TAG" "$REPO_ROOT"
kind load docker-image --name "$CLUSTER_NAME" "edge-migrate:$IMAGE_TAG"

# ---- bundled -----------------------------------------------------------------
section "BUNDLED — helm install $RELEASE -> ns/$BUNDLED_NS (Postgres, Redis, NATS from the chart)"
h install "$RELEASE" "$CHART" -n "$BUNDLED_NS" --create-namespace "${MIGRATE_SET[@]}" "${CLIENT_SET[@]}" --wait --timeout 10m
[ "$(release_status "$BUNDLED_NS")" = deployed ] || die "release is $(release_status "$BUNDLED_NS"), not deployed"
for s in postgres redis nats; do
  wait_rollout "statefulset/$RELEASE-$s" "$BUNDLED_NS" 60s
  [ "$(k -n "$BUNDLED_NS" get pvc "data-$RELEASE-$s-0" -o jsonpath='{.status.phase}')" = Bound ] \
    || die "$s has no bound volume"
done
ok "Postgres, Redis and NATS Ready, each on a bound volume"
assert_migrated "$BUNDLED_NS" "app.kubernetes.io/name=postgres" edge
client_check "$BUNDLED_NS"
h test "$RELEASE" -n "$BUNDLED_NS" --logs --timeout 5m || die "helm test $RELEASE did not pass"
ok "helm test $RELEASE: the chart's own test pods reached Postgres, Redis and NATS with the connection Secret"

section "BUNDLED — an upgrade keeps the credentials"
before="$(k -n "$BUNDLED_NS" get secret "$SECRET" -o json | jq -cS .data)"
h upgrade "$RELEASE" "$CHART" -n "$BUNDLED_NS" "${MIGRATE_SET[@]}" "${CLIENT_SET[@]}" --wait --timeout 10m
after="$(k -n "$BUNDLED_NS" get secret "$SECRET" -o json | jq -cS .data)"
[ "$before" = "$after" ] || die "the upgrade changed the connection Secret — the datastores keep their first-start passwords, so clients would be locked out"
ok "connection Secret unchanged by the upgrade"
client_check "$BUNDLED_NS"

# ---- external ----------------------------------------------------------------
section "EXTERNAL — datastores the chart did not create, in ns/$INFRA_NS"
k apply -f "$LOCAL_DIR/manifests/namespaces.yaml" >/dev/null
k apply -f "$LOCAL_DIR/manifests/postgres.yaml" -f "$LOCAL_DIR/manifests/nats.yaml" >/dev/null
k -n "$INFRA_NS" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: redis, labels: { app: redis } }
spec:
  selector: { matchLabels: { app: redis } }
  template:
    metadata: { labels: { app: redis } }
    spec:
      containers:
        - name: redis
          image: $REDIS_IMAGE
          args: ["redis-server", "--requirepass", "$EXT_REDIS_PASSWORD"]
          ports: [{ containerPort: 6379 }]
---
apiVersion: v1
kind: Service
metadata: { name: redis }
spec:
  selector: { app: redis }
  ports: [{ port: 6379 }]
EOF
for d in postgres nats redis; do wait_rollout "deploy/$d" "$INFRA_NS" 240s; done
[ "$(psql_in "$INFRA_NS" app=postgres postgres edge "select count(*) from information_schema.tables where table_schema='public'")" = 0 ] \
  || die "the external Postgres already has tables — the migration below would prove nothing"
ok "external Postgres, Redis and NATS up; the edge database is empty"

PGH="postgres.$INFRA_NS.svc.cluster.local"
EXT_VALUES="$(mktemp)"
cat >"$EXT_VALUES" <<EOF
postgres: { enabled: false }
redis: { enabled: false }
nats: { enabled: false }
external:
  postgres:
    dsn: postgres://postgres:edgedevpass@$PGH:5432/edge?sslmode=disable
    issuerDsn: postgres://postgres:edgedevpass@$PGH:5432/issuer?sslmode=disable
  redis:
    addr: redis.$INFRA_NS.svc.cluster.local:6379
    password: $EXT_REDIS_PASSWORD
  nats:
    url: nats://nats.$INFRA_NS.svc.cluster.local:4222
EOF
section "EXTERNAL — helm install $RELEASE -> ns/$EXTERNAL_NS (all three switched off)"
h install "$RELEASE" "$CHART" -n "$EXTERNAL_NS" --create-namespace -f "$EXT_VALUES" "${MIGRATE_SET[@]}" --wait --timeout 10m
rm -f "$EXT_VALUES"
[ "$(release_status "$EXTERNAL_NS")" = deployed ] || die "release is $(release_status "$EXTERNAL_NS"), not deployed"
[ -z "$(k -n "$EXTERNAL_NS" get statefulset,pvc -o name)" ] || die "external mode created a datastore of its own"
ok "release deployed with no datastore of its own"
assert_migrated "$INFRA_NS" app=postgres postgres
client_check "$EXTERNAL_NS"
