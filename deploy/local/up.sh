#!/usr/bin/env bash
# up.sh — reproducible LOCAL standup for edge-infra on kind.
#
#   git clone  ->  deploy/local/up.sh  ->  a routable local gateway (two tenants).
#
# Idempotent + re-runnable: an existing cluster is reused, manifests re-apply as
# no-ops, secrets/certs are not duplicated. Phases run in order and each is
# guarded so a re-run resumes cleanly.
#
# Usage:
#   deploy/local/up.sh                    # run all implemented phases
#   CLUSTER_NAME=foo deploy/local/up.sh   # override the cluster name
#
# Phases (built incrementally; see deploy/local/README.md):
#   1  kind cluster (no default CNI) + Calico
#   2  cluster deps: cert-manager, Kyverno, Postgres, NATS
#   3  build local images (all 7 targets) + load into the cluster
#   4  data-plane PKI (the edge-pki chart: the CAs; each chart issues its own certificate)
#   5  admin PKI (bootstrap-pki.sh) + app secrets
#   6  migrate the shared DB (control-plane + OSB schemas)
#   7  deploy all charts with the local overlays, extAuthz at its chart default (ON)
#   8  seed two tenant backends + a gateway/route per tenant
#   9  prove routable: a request per tenant through the node :443 hostPort
#  25  fresh install: an OSB service with the default jwt auth answers 401
#      without a token and 200 with one (runs right after 9, before phase 12
#      ever touches ext_authz)
#  10  SEC-3 Property 1 — Kyverno admission rejects open rules (red-first)
#  11  SEC-3 Property 2 — Calico drops the bypass hop, gateway stays allowed
#  12  CFG-1 flip + ext_authz LIVE — four properties, red-first, one at a time
#  13  R8 fail-static inconsistent-snapshot guard (live, red-first)
#  14  fail-static guard counters exported as metrics (live, red-first)
#  15  OSB broker answers; a service it provisions is served through Envoy
#  16  two nodes serve two tenants; each node's SDS holds only its own key (XDS-1)
#  17  the charts' NetworkPolicies refuse a pod outside the allowed flows (red-first)
#  18  a user created through SCIM signs in through OIDC (Dex as the IdP)
#  19  confidential compute: the workload starts only with a verified attestation
#  20  one HTTPS port serves two hosts, each with its own per-route cert (SNI)
#  21  an OSB HTTPS service: public host's cert + stub body via a DNS upstream
#  22  a second :443 gateway is refused and :443 keeps serving (red-first)
#  23  forged identity headers are stripped; a path traversal is refused
#  24  every listener access-logs and traces; the OTel collector shows curl's x-request-id
#  26  an unsigned first-party image is refused at admission; a signed one is
#      admitted pinned to its digest (red-first, runs right after 10)
#  27  csi-driver-spiffe issues agent pods their SVIDs; with the trust bundle
#      over SDS, a pod without one is refused at the TLS handshake
#  28  edge-egress: an agent reaches a mock TLS provider only through it —
#      direct dropped, CONNECT and proxied HTTP served, unlisted hosts 403
#  29  egress lockdown: Kyverno default-denies egress in a namespace labelled
#      talyvor.io/agents=true — the direct call dropped, the same call through
#      edge-egress served, the deleted policy written back
#  32  no internet at run time: no node has a route to a public address and
#      CoreDNS no upstream; every Edge workload restarts cold and serves, auth-service
#      reads every issuer's keys from inside the cluster, and CoreDNS logs no
#      query for a name outside it
#  33  KEK rotation: every key re-sealed under a new SECRET_KEK, the old one
#      dropped, and a fresh Envoy still served the same cert over SDS
#  34  `helm test` passes for every release this run installed — each chart's
#      own test pod reaches its service through the Service and the chart's
#      NetworkPolicy (runs before 32, which cuts the image registry off)
#  36  an agent's own ServiceAccount token, projected for the gateway's
#      audience, gets 200 from an OSB service and its token for another audience
#      401; auth-service fetches the API server's keys with its own token
#  35  offline licence: a valid licence reads edge_licence_valid 1; replaced by an
#      expired one it reads 0 and the control plane warns, and both tenants still
#      return 200, through a cold restart and a fresh Envoy (runs last)
#
# One command for the whole thing, cluster created and deleted:  make kind-e2e
#
# Run a single phase for iteration, e.g.:  deploy/local/up.sh phase3_images
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq openssl

# ---- Phase 1 — cluster + Calico ---------------------------------------------
phase1_cluster() {
  section "PHASE 1 — kind cluster '$CLUSTER_NAME' (default CNI disabled) + Calico"

  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "cluster '$CLUSTER_NAME' already exists — reusing"
  else
    # NB: kept array-free for bash 3.2 (macOS default) — an empty "${arr[@]}"
    # trips `set -u` there.
    if [ -n "$KIND_NODE_IMAGE" ]; then
      kind create cluster --name "$CLUSTER_NAME" \
        --config "$LOCAL_DIR/kind-config.yaml" --image "$KIND_NODE_IMAGE"
    else
      kind create cluster --name "$CLUSTER_NAME" \
        --config "$LOCAL_DIR/kind-config.yaml"
    fi
    ok "cluster created"
  fi
  k version --request-timeout=10s >/dev/null 2>&1 || k cluster-info >/dev/null \
    || die "kubectl cannot reach context $KUBE_CONTEXT"

  # Calico enforces NetworkPolicy (kindnet does not). Nodes stay NotReady until
  # the CNI is up, so install BEFORE waiting on node readiness.
  if k get ds calico-node -n kube-system >/dev/null 2>&1; then
    log "Calico already installed — reusing"
  else
    section "installing Calico $CALICO_VERSION"
    k apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
  fi

  wait_nodes_ready 300s
  section "waiting for Calico control plane"
  k -n kube-system rollout status ds/calico-node --timeout=300s
  k -n kube-system rollout status deploy/calico-kube-controllers --timeout=300s

  # kind nodes share ONE subnet, so IPIP encapsulation is unnecessary — and it
  # actively breaks the SEC-3 gateway-allow: with ipipMode=Always, cross-node
  # hostNetwork traffic (the edge-proxy gateway) egresses via tunl0 and takes the
  # tunnel's POD-CIDR IP as source, which would NOT match a node-CIDR ipBlock allow.
  # CrossSubnet => native routing for same-subnet nodes => the node IP is preserved
  # as source (gateway matches NODE_CIDR), while pod sources stay real (the SEC-3
  # drop still bites). Applied here, before any workload, so every connection is
  # native from the start.
  if k get ippool default-ipv4-ippool >/dev/null 2>&1; then
    k patch ippool default-ipv4-ippool --type merge -p '{"spec":{"ipipMode":"CrossSubnet"}}' >/dev/null \
      && ok "Calico ipipMode=CrossSubnet (node-IP source preserved for same-subnet nodes)" \
      || warn "could not patch Calico IPPool to CrossSubnet"
  fi
  ok "Calico running"
}

verify_phase1() {
  section "VERIFY Phase 1"
  k get nodes -o wide
  echo
  k get pods -n kube-system -l k8s-app=calico-node -o wide
  echo
  k get networkpolicies -A >/dev/null \
    && ok "NetworkPolicy API reachable — enforcement path is live" \
    || die "NetworkPolicy API not reachable"
  ok "Phase 1 verified"
}

# ---- Phase 2 — cluster dependencies -----------------------------------------
phase2_deps() {
  section "PHASE 2 — cluster deps (cert-manager, Kyverno, Postgres, NATS)"

  log "namespaces (infra, edge)"
  k apply -f "$LOCAL_DIR/manifests/namespaces.yaml"

  if k get deploy cert-manager -n cert-manager >/dev/null 2>&1; then
    log "cert-manager already installed — reusing"
  else
    section "installing cert-manager $CERT_MANAGER_VERSION"
    k apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
  fi
  section "waiting for cert-manager"
  k -n cert-manager wait --for=condition=Available deploy --all --timeout=300s
  ok "cert-manager ready"

  if k get crd clusterpolicies.kyverno.io >/dev/null 2>&1 \
     && k get deploy kyverno-admission-controller -n kyverno >/dev/null 2>&1; then
    log "Kyverno already installed — reusing"
  else
    section "installing Kyverno $KYVERNO_VERSION (server-side — its CRDs exceed the client-side annotation limit)"
    k apply --server-side --force-conflicts \
      -f "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"
  fi
  section "waiting for Kyverno (engine only — SEC-3 policies are a later run)"
  k -n kyverno wait --for=condition=Available deploy --all --timeout=300s
  ok "Kyverno ready"

  section "Postgres (dev, in $INFRA_NS)"
  k apply -f "$LOCAL_DIR/manifests/postgres.yaml"
  wait_rollout deploy/postgres "$INFRA_NS" 240s
  ok "Postgres ready"

  section "NATS (dev JetStream, in $INFRA_NS)"
  k apply -f "$LOCAL_DIR/manifests/nats.yaml"
  wait_rollout deploy/nats "$INFRA_NS" 240s
  ok "NATS ready"
}

verify_phase2() {
  section "VERIFY Phase 2"
  k get pods -n cert-manager
  echo
  k get pods -n kyverno
  echo
  k get pods,svc -n "$INFRA_NS" -l part-of=edge-local
  echo
  # Prove the shared DB actually accepts queries and both databases exist.
  local pgpod
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select 'edge db reachable, datnames='||string_agg(datname,',') from pg_database where datname in ('edge','issuer');" \
    && ok "Postgres serving; edge + issuer databases present"
  ok "Phase 2 verified"
}

# ---- Phase 3 — build + load local images ------------------------------------
# Extends `make docker-build-local` (which builds only server/osb/auth-service):
# builds ALL seven images the charts need and loads them into the kind nodes.
# The control-plane Dockerfile compiles its 5 Go binaries once in a shared builder
# layer, so issuer/ratelimit/secrets/migrate are cheap after `server`. Rust
# (auth-service) builds IN-container (BUILD_MODE=local) so the binary is linux/*,
# not the host's darwin/arm64.
#
# IMAGE_SOURCE=registry (make release-e2e) builds nothing: it pulls the eight
# images the charts pin — deploy/hack/release-pin.sh --list, one tag for all —
# and loads those under the same local names, so every later phase runs the
# released images instead of the working tree.
build_local_images() {
  section "PHASE 3 — build local images (tag ':$IMAGE_TAG') + load into kind"

  section "control-plane Go binaries (server, issuer, ratelimit, secrets, migrate, attest)"
  docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target server \
    -t "edge-control-plane:$IMAGE_TAG" "$REPO_ROOT"
  local tgt
  for tgt in issuer ratelimit secrets migrate attest; do
    docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target "$tgt" \
      -t "edge-$tgt:$IMAGE_TAG" "$REPO_ROOT"
  done

  section "edge-osb (Python) image"
  docker build -f "$REPO_ROOT/osb/Dockerfile" -t "edge-osb:$IMAGE_TAG" "$REPO_ROOT"

  section "auth-service (Rust, built in-container so the binary is linux)"
  docker build -f "$REPO_ROOT/auth-service/Dockerfile" \
    --build-arg BUILD_MODE=local -t "auth-service:$IMAGE_TAG" "$REPO_ROOT/auth-service"
}

pull_release_images() {
  section "PHASE 3 — pull the release-pinned images (no build) + load into kind as ':$IMAGE_TAG'"
  local refs ref r name
  refs="$(bash "$REPO_ROOT/deploy/hack/release-pin.sh" --list)" \
    || die "the charts do not pin one release tag — run deploy/hack/release-pin.sh <tag> first"
  for name in edge-control-plane edge-issuer edge-ratelimit edge-secrets edge-migrate \
              edge-attest edge-osb auth-service; do
    ref=""
    while IFS= read -r r; do
      case "$r" in */"$name":*) ref="$r" ;; esac
    done <<<"$refs"
    [ -n "$ref" ] || die "no chart pins $name — the release would not run it"
    docker pull "$ref" || die "cannot pull $ref — is it pushed, and are you logged in to its registry?"
    docker tag "$ref" "$name:$IMAGE_TAG"
    ok "$name:$IMAGE_TAG <- $ref"
  done
}

phase3_images() {
  case "$IMAGE_SOURCE" in
    build)    build_local_images ;;
    registry) pull_release_images ;;
    *) die "IMAGE_SOURCE is '$IMAGE_SOURCE' — build (the default) or registry" ;;
  esac

  section "pulling public images (envoy, busybox, the charts' test image)"
  docker pull "$ENVOY_IMAGE"
  docker pull "$BUSYBOX_IMAGE"
  docker pull "$TEST_IMAGE"

  section "kind load — importing images onto the cluster nodes"
  local img
  for img in \
    "edge-control-plane:$IMAGE_TAG" "edge-issuer:$IMAGE_TAG" \
    "edge-ratelimit:$IMAGE_TAG" "edge-secrets:$IMAGE_TAG" \
    "edge-migrate:$IMAGE_TAG" "edge-osb:$IMAGE_TAG" "auth-service:$IMAGE_TAG" \
    "edge-attest:$IMAGE_TAG"; do
    kind load docker-image --name "$CLUSTER_NAME" "$img"
  done
  # Public images: best-effort (the node can still pull them at runtime).
  for img in "$ENVOY_IMAGE" "$BUSYBOX_IMAGE" "$TEST_IMAGE"; do
    kind load docker-image --name "$CLUSTER_NAME" "$img" \
      || warn "kind load $img failed — node will pull it at runtime"
  done
  ok "images built + loaded"
}

verify_phase3() {
  section "VERIFY Phase 3 — local images present on a worker node"
  docker exec "${CLUSTER_NAME}-worker" crictl images 2>/dev/null \
    | grep -E 'edge-(control-plane|issuer|ratelimit|secrets|migrate|osb)|auth-service|envoyproxy/envoy' \
    || die "expected local images not found on node ${CLUSTER_NAME}-worker"
  ok "Phase 3 verified"
}

# ---- Phase 4 — data-plane PKI (the edge-pki chart) ---------------------------
# The CAs only. No certificate is applied by hand: each chart issues its own
# from edge-internal-ca when Phase 7 installs it (B28.237).
phase4_dataplane_pki() {
  section "PHASE 4 — data-plane PKI (helm install edge-pki: the internal CA and the agent CA)"
  h upgrade --install edge-pki "$REPO_ROOT/deploy/helm/edge-pki" -n cert-manager \
    --wait --timeout 180s
  k wait --for=condition=Ready clusterissuer/edge-internal-ca clusterissuer/edge-spiffe --timeout=120s
  ok "edge-internal-ca and edge-spiffe Ready"
}

verify_phase4() {
  section "VERIFY Phase 4 — the CAs come from the edge-pki release"
  local i rel
  for i in edge-internal-ca edge-spiffe; do
    rel="$(k get clusterissuer "$i" -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}')"
    [ "$rel" = edge-pki ] || die "ClusterIssuer $i is not from the edge-pki release (release '$rel')"
    ok "clusterissuer/$i <- helm release edge-pki"
  done
  ok "Phase 4 verified"
}

# ---- Phase 5 — admin PKI (bootstrap-pki.sh) + app secrets -------------------
phase5_secrets() {
  section "PHASE 5 — admin PKI + app secrets"
  local PKI="$LOCAL_DIR/.pki-bootstrap"

  # 1. Admin-plane PKI material — reuse if already generated so the KEK stays
  #    stable across re-runs (the control-plane must share it with the custodian).
  if [ -f "$PKI/admin-ca.crt" ] && [ -f "$PKI/server.crt" ] \
     && [ -f "$PKI/server.key" ] && [ -f "$PKI/secret_kek.b64" ]; then
    log "reusing admin PKI material in .pki-bootstrap"
  else
    section "generating admin PKI (scripts/bootstrap-pki.sh)"
    rm -rf "$PKI"
    # Redirect stdout: the banner echoes the KEK — keep it out of logs.
    EDGE_NAMESPACE="$INFRA_NS" bash "$REPO_ROOT/scripts/bootstrap-pki.sh" "$PKI" >/dev/null
  fi
  local KEK; KEK="$(cat "$PKI/secret_kek.b64")"

  # 2. Issuer RSA signing key (kid=k1) — reuse if present. activeKid is set in the
  #    Phase-7 issuer overlay to match.
  [ -f "$PKI/k1.pem" ] || openssl genrsa -out "$PKI/k1.pem" 2048 2>/dev/null

  # 3. Gateway transit-assertion key (Ed25519) — reuse if present. P1 verifies
  #    the injected x-gateway-auth against its public half.
  [ -f "$PKI/transit.pem" ] || openssl genpkey -algorithm ed25519 -out "$PKI/transit.pem" 2>/dev/null \
    || die "openssl could not generate the Ed25519 transit key (needs OpenSSL 3)"

  # DSNs — sslmode=disable locally (prod uses TLS). One shared 'edge' DB for
  # control-plane + osb + secrets; issuer has its own 'issuer' DB.
  local PGH="postgres.${INFRA_NS}.svc.cluster.local"
  local SHARED_DSN="postgres://postgres:edgedevpass@${PGH}:5432/edge?sslmode=disable"
  local OSB_DSN="postgresql://postgres:edgedevpass@${PGH}:5432/edge?sslmode=disable"
  local ISSUER_DSN="postgres://postgres:edgedevpass@${PGH}:5432/issuer?sslmode=disable"
  local ISSUER_URL="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"
  local AUD="edge-gateway"

  section "app + custodian secrets in $INFRA_NS"
  # control-plane: shared-DB DSN (key 'dsn') + SECRET_KEK
  apply_secret "$INFRA_NS" generic edge-control-plane-postgres \
    --from-literal=dsn="$SHARED_DSN" \
    --from-literal=SECRET_KEK="$KEK"

  # edge-osb: same shared DB + NATS. ALLOW_UNTENANTED lets the broker boot with
  # zero tenant_api_keys (dev); DB/NATS TLS is turned off via the Phase-7 overlay.
  apply_secret "$INFRA_NS" generic edge-osb-secrets \
    --from-literal=DATABASE_URL="$OSB_DSN" \
    --from-literal=DB_SSL_MODE="disable" \
    --from-literal=NATS_URL="nats://nats.${INFRA_NS}.svc.cluster.local:4222" \
    --from-literal=ALLOW_UNTENANTED="true"

  # edge-issuer: its own DB + iss/aud (self-migrated by the chart's migrate Job).
  # SCIM + OIDC sign-in are on from the start: the IdP (Dex, Phase 18) is
  # discovered on first sign-in, so the issuer boots without it.
  apply_secret "$INFRA_NS" generic issuer-secrets \
    --from-literal=ISSUER_URL="$ISSUER_URL" \
    --from-literal=ISSUER_AUDIENCE="$AUD" \
    --from-literal=ISSUER_DATABASE_URL="$ISSUER_DSN" \
    --from-literal=ISSUER_SCIM_TOKEN="$SCIM_TOKEN" \
    --from-literal=ISSUER_OIDC_ISSUER="https://dex.${INFRA_NS}.svc.cluster.local:5556/dex" \
    --from-literal=ISSUER_OIDC_CLIENT_ID="edge-issuer" \
    --from-literal=ISSUER_OIDC_CLIENT_SECRET="local-dev-dex-client-secret" \
    --from-literal=ISSUER_OIDC_REDIRECT_URL="${ISSUER_URL}/sso/callback"
  apply_secret "$INFRA_NS" generic issuer-signing-keys \
    --from-file=k1.pem="$PKI/k1.pem"

  # auth-service: JWKS -> issuer (https + SAN match); iss/aud match; transit key.
  apply_secret "$INFRA_NS" generic auth-service-secrets \
    --from-literal=JWKS_URL="${ISSUER_URL}/.well-known/jwks.json" \
    --from-literal=JWT_ISSUER="$ISSUER_URL" \
    --from-literal=JWT_AUDIENCE="$AUD" \
    --from-file=TRANSIT_SIGNING_KEY="$PKI/transit.pem"

  # edge-secrets custodian (out-of-band admin PKI from bootstrap-pki.sh).
  apply_secret "$INFRA_NS" generic edge-admin-ca \
    --from-file=ca.crt="$PKI/admin-ca.crt"
  apply_secret "$INFRA_NS" tls edge-secrets-tls \
    --cert="$PKI/server.crt" --key="$PKI/server.key"
  apply_secret "$INFRA_NS" generic edge-secrets-config \
    --from-literal=SECRET_KEK="$KEK" \
    --from-literal=SECRETS_DATABASE_URL="$SHARED_DSN" \
    --from-literal=SECRETS_ADMIN_API_KEY="local-dev-admin-key"

  ok "secrets created"
}

verify_phase5() {
  section "VERIFY Phase 5 — all referenced app secrets exist in $INFRA_NS"
  local s ok_all=1
  for s in edge-control-plane-postgres edge-osb-secrets issuer-secrets \
           issuer-signing-keys auth-service-secrets edge-admin-ca \
           edge-secrets-tls edge-secrets-config; do
    if k -n "$INFRA_NS" get secret "$s" >/dev/null 2>&1; then ok "$s"; else warn "MISSING $s"; ok_all=0; fi
  done
  [ "$ok_all" = 1 ] || die "some app secrets are missing"
  ok "Phase 5 verified"
}

# ---- Phase 6 — migrate the shared DB ----------------------------------------
phase6_migrate() {
  section "PHASE 6 — migrate the shared 'edge' DB (control-plane + OSB schemas)"
  # Job is not re-appliable once complete; recreate it (migrate is idempotent).
  k -n "$INFRA_NS" delete job edge-migrate-shared --ignore-not-found >/dev/null 2>&1 || true
  k apply -f "$LOCAL_DIR/manifests/migrate-job.yaml"
  section "waiting for the migrate Job to complete"
  if ! k -n "$INFRA_NS" wait --for=condition=complete job/edge-migrate-shared --timeout=180s 2>/dev/null; then
    warn "migrate Job did not report complete — logs:"
    k -n "$INFRA_NS" logs job/edge-migrate-shared || true
    die "migrate Job failed"
  fi
  k -n "$INFRA_NS" logs job/edge-migrate-shared | tail -25
  ok "migrations applied"
}

verify_phase6() {
  section "VERIFY Phase 6 — schema present in the shared 'edge' DB"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  echo "  public tables:"
  k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select string_agg(table_name, ', ' order by table_name) from information_schema.tables where table_schema='public';"
  local core
  core="$(k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select count(*) from information_schema.tables where table_schema='public' and table_name in ('gateways','routes','clusters','endpoints');" | tr -d '[:space:]')"
  [ "$core" = "4" ] || die "core routing tables missing (gateways/routes/clusters/endpoints found: $core/4)"
  ok "Phase 6 verified (control-plane + OSB schema present)"
}

# ---- Phase 7 — deploy all charts (extAuthz ON, the chart default) -----------
# helm_install <release> <namespace> — chart default values.yaml is implicit;
# layer the local overlay (if present). --wait blocks until Ready so the next
# chart's dependency is satisfied.
helm_install() {
  local rel="$1" ns="$2" suffix
  suffix="${rel#edge-}"
  local chart="$REPO_ROOT/deploy/helm/$rel"
  local loc="$LOCAL_DIR/values/values-${suffix}.yaml"
  section "helm upgrade --install $rel -> ns/$ns"
  # Clear a prior stuck/failed release (e.g. a hook that timed out) so a re-run
  # proceeds cleanly instead of erroring on "another operation in progress".
  local st
  st="$(h status "$rel" -n "$ns" -o json 2>/dev/null | jq -r '.info.status // empty' 2>/dev/null || true)"
  case "$st" in
    pending-install|pending-upgrade|pending-rollback|failed|uninstalling)
      warn "clearing prior '$st' release $rel"
      h uninstall "$rel" -n "$ns" >/dev/null 2>&1 || true
      k -n "$ns" delete job "${rel}-migrate" --ignore-not-found >/dev/null 2>&1 || true ;;
  esac
  set -- upgrade --install "$rel" "$chart" -n "$ns" --create-namespace
  if [ -f "$loc" ]; then set -- "$@" -f "$loc"; fi
  set -- "$@" --wait --timeout "${HELM_TIMEOUT:-300s}"
  h "$@"
}

diag_fail() {  # <release> <ns> — dump why a chart didn't come up, then stop.
  warn "deploy failed for $1 (ns $2) — diagnostics:"
  k -n "$2" get pods -o wide 2>/dev/null || true
  echo "  recent events:"
  k -n "$2" get events --sort-by=.lastTimestamp 2>/dev/null | tail -15 || true
  die "chart $1 failed to become Ready"
}

phase7_deploy() {
  section "PHASE 7 — deploy charts (local overlays, extAuthz ON — the chart default)"
  # The local overlays switch the charts' NetworkPolicies on with the gateway
  # (hostNetwork edge-proxy) allowed from 172.16.0.0/12. A node outside it
  # would be cut off from the control-plane, so stop here rather than later.
  local nip
  for nip in $(k get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' | grep -E '^[0-9.]+$'); do
    in_gateway_cidr "$nip" || die "node IP $nip is outside 172.16.0.0/12, the gateway CIDR in deploy/local/values — set networkPolicy.gatewayCIDRs to this cluster's node network"
  done
  # Order encodes dependencies: control-plane (xDS) first; issuer before
  # auth-service (which fetches the issuer JWKS at startup); proxy after the
  # control-plane is serving xDS.
  helm_install edge-control-plane "$INFRA_NS" || diag_fail edge-control-plane "$INFRA_NS"
  helm_install edge-issuer        "$INFRA_NS" || diag_fail edge-issuer "$INFRA_NS"
  helm_install auth-service       "$INFRA_NS" || diag_fail auth-service "$INFRA_NS"
  helm_install edge-osb           "$INFRA_NS" || diag_fail edge-osb "$INFRA_NS"
  helm_install edge-proxy         edge        || diag_fail edge-proxy edge
  # Auxiliary charts (not on the routing path). Best-effort so the run isn't
  # blocked if a custodian/RLS detail needs tuning.
  helm_install edge-ratelimit "$INFRA_NS" || warn "edge-ratelimit not Ready (auxiliary — continuing)"
  helm_install edge-secrets   "$INFRA_NS" || warn "edge-secrets not Ready (auxiliary — continuing)"
  ok "charts deployed"
}

verify_phase7() {
  section "VERIFY Phase 7 — services Ready + Envoy connected to control-plane"
  k get pods -n "$INFRA_NS" -o wide
  echo; k get pods -n edge -o wide
  echo
  # Envoy admin is localhost-only in the pod (R7); reach it via a short-lived
  # port-forward and confirm the xDS connection is up.
  local ep
  ep="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$ep" ] || ep="$(k -n edge get pod -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "$ep" ]; then
    section "edge-proxy admin ($ep) — xDS link + received config"
    # kubectl directly (see envoy_config_dump): a backgrounded k() leaks the forward.
    kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$ep" 19001:9901 >/dev/null 2>&1 &
    local pf=$!; sleep 3
    echo "  control_plane connection (1 = connected):"
    curl -s --max-time 5 http://127.0.0.1:19001/stats 2>/dev/null \
      | grep -E 'control_plane\.(connected_state|identifier)' | sed 's/^/    /' || true
    echo "  received listeners / clusters:"
    curl -s --max-time 5 http://127.0.0.1:19001/config_dump 2>/dev/null \
      | jq -r '[.configs[]?.dynamic_listeners[]?]|length as $l|null|"    dynamic_listeners=\($l)"' 2>/dev/null || true
    curl -s --max-time 5 http://127.0.0.1:19001/config_dump 2>/dev/null \
      | jq -r '[.configs[]?.dynamic_active_clusters[]?]|length as $c|null|"    dynamic_active_clusters=\($c)"' 2>/dev/null || true
    kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  fi
  verify_chart_certificates
  ok "Phase 7 verified (all required charts Ready via --wait)"
}

# Every certificate the stack serves or presents was issued by the chart that
# uses it — nothing in infra or edge was applied by hand (B28.237).
verify_chart_certificates() {
  section "VERIFY — every Certificate is a chart's, Ready, and its Secret exists"
  local ns s n=0 name rel ready
  for ns in "$INFRA_NS" edge; do
    k -n "$ns" wait --for=condition=Ready certificate --all --timeout=120s >/dev/null \
      || die "a certificate in $ns was not issued"
    while IFS='|' read -r name rel ready; do
      [ -n "$name" ] || continue
      [ -n "$rel" ] || die "certificate $ns/$name belongs to no helm release — applied by hand"
      [ "$ready" = True ] || die "certificate $ns/$name (release $rel) is not Ready"
      ok "certificate $ns/$name <- helm release $rel, Ready"
      n=$((n + 1))
    done < <(k -n "$ns" get certificate -o json | jq -r '.items[] | [.metadata.name,
      (.metadata.annotations["meta.helm.sh/release-name"] // ""),
      ((.status.conditions // [])[] | select(.type == "Ready") | .status)] | join("|")')
  done
  for s in auth-service-tls-secret edge-cp-tls-secret issuer-tls-secret; do
    k -n "$INFRA_NS" get secret "$s" >/dev/null 2>&1 || die "MISSING $INFRA_NS/$s"
  done
  for s in envoy-serving-tls-secret envoy-xds-client-tls-secret envoy-authz-client-tls-secret; do
    k -n edge get secret "$s" >/dev/null 2>&1 || die "MISSING edge/$s"
  done
  [ "$n" -ge 6 ] || die "expected at least 6 chart certificates, found $n"
  ok "$n certificates, every one issued by the chart that uses it"
}

# ---- Phase 8 — seed two tenants (backends + gateway/route) -------------------
phase8_seed() {
  section "PHASE 8 — seed two tenant backends + a gateway/route per tenant"
  # Preload the echo image (a tag, so kind load works), then the two backends.
  if docker pull "$ECHO_IMAGE" >/dev/null 2>&1; then
    kind load docker-image --name "$CLUSTER_NAME" "$ECHO_IMAGE" >/dev/null 2>&1 || true
  else
    warn "echo image not preloaded — nodes will pull at runtime"
  fi
  k apply -f "$LOCAL_DIR/manifests/tenants.yaml"
  wait_rollout deploy/echo tenant-a 120s
  wait_rollout deploy/echo tenant-b 120s

  local ipA ipB pgpod
  ipA="$(k -n tenant-a get svc echo -o jsonpath='{.spec.clusterIP}')"
  ipB="$(k -n tenant-b get svc echo -o jsonpath='{.spec.clusterIP}')"
  [ -n "$ipA" ] && [ -n "$ipB" ] || die "could not resolve echo Service ClusterIPs"
  log "tenant-a echo=$ipA:5678   tenant-b echo=$ipB:5678"

  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  section "seeding gateway 'local-gw' (HTTP :443) + 2 host-routes (auth_policy=none)"
  # This is the missing route source. Direct SQL (a tiny seed helper) mirrors
  # translator.apply_create's columns but: (1) a plaintext-HTTP listener on :443
  # to match the node hostPort, (2) upstream DECOUPLED from the match host (echo
  # ClusterIP), and (3) auth_policy='none' — these are the unauthenticated
  # baseline every later phase probes without a token, and they must keep
  # serving when phase 12 switches ext_authz off (the reconciler withholds the
  # WHOLE snapshot if any route wants auth while ext_authz is off).
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<SQL
BEGIN;
INSERT INTO gateways (id, name, port, protocol, node_selector)
VALUES ('local-gw','local-gw',443,'HTTP','{}'::jsonb)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port, protocol=EXCLUDED.protocol, updated_at=now();

INSERT INTO clusters (id,name) VALUES ('tenant-a','tenant-a') ON CONFLICT (name) DO NOTHING;
DELETE FROM endpoints WHERE cluster_id='tenant-a';
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('tenant-a-0','tenant-a','${ipA}',5678,1);
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('tenant-a','tenant-a','local-gw',ARRAY['tenant-a.local']::text[],'/','tenant-a',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,timeout_seconds=EXCLUDED.timeout_seconds,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;

INSERT INTO clusters (id,name) VALUES ('tenant-b','tenant-b') ON CONFLICT (name) DO NOTHING;
DELETE FROM endpoints WHERE cluster_id='tenant-b';
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('tenant-b-0','tenant-b','${ipB}',5678,1);
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('tenant-b','tenant-b','local-gw',ARRAY['tenant-b.local']::text[],'/','tenant-b',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,timeout_seconds=EXCLUDED.timeout_seconds,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;
COMMIT;
SQL
  ok "routes seeded in Postgres"
}

verify_phase8() {
  section "VERIFY Phase 8 — routes in Postgres AND published to Envoy"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  echo "  routes (Postgres):"
  k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select r.name||': host='||array_to_string(r.hosts,',')||' -> '||r.cluster_name||' (auth='||r.auth_policy||') on '||g.name||':'||g.port||'/'||g.protocol from routes r join gateways g on g.id=r.gateway_id where r.deleted_at is null order by 1;" \
    | sed 's/^/    /'

  # Reconciler polls Postgres every ~5s; wait for the snapshot to reach Envoy.
  local ep dump i=0
  ep="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].metadata.name}')"
  while [ "$i" -lt 10 ]; do
    dump="$(envoy_config_dump "$ep")"
    if has "$dump" tenant-a && has "$dump" tenant-b; then break; fi
    i=$((i + 1)); sleep 2
  done
  echo "  Envoy listeners:"
  printf '%s' "$dump" | jq -r '.configs[]?.dynamic_listeners[]?.active_state.listener | "    "+(.name//"?")+" on :"+((.address.socket_address.port_value//0)|tostring)' 2>/dev/null | sort -u || true
  echo "  Envoy clusters:"
  printf '%s' "$dump" | jq -r '.configs[]?.dynamic_active_clusters[]?.cluster.name | "    "+.' 2>/dev/null | sort -u || true
  echo "  Envoy vhost domains (Host match):"
  printf '%s' "$dump" | jq -r '.configs[]?.dynamic_route_configs[]?.route_config.virtual_hosts[]?.domains[]? | "    "+.' 2>/dev/null | sort -u || true
  if has "$dump" tenant-a && has "$dump" tenant-b; then
    ok "both tenant routes published to Envoy (control-plane -> xDS)"
  else
    die "Envoy config_dump does not show both tenant routes"
  fi
}

# ---- Phase 9 — prove routable ------------------------------------------------
phase9_prove() {
  local hp="${GATEWAY_HOST_PORT:-443}"
  section "PHASE 9 — PROVE ROUTABLE (each tenant via node :$hp hostPort, auth_policy=none)"
  local i=0 ca cb a b cn
  # Retry briefly: the :443 listener may land a beat after the clusters.
  while [ "$i" -lt 10 ]; do
    ca="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: tenant-a.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
    cb="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: tenant-b.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
    [ "$ca" = 200 ] && [ "$cb" = 200 ] && break
    i=$((i + 1)); sleep 3
  done
  a="$(curl -s --max-time 6 -H 'Host: tenant-a.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
  b="$(curl -s --max-time 6 -H 'Host: tenant-b.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
  cn="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: nope.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
  echo "  http://127.0.0.1:${hp}/  -H 'Host: tenant-a.local'  ->  HTTP $ca   body: $(printf '%s' "$a" | tr -d '\n')"
  echo "  http://127.0.0.1:${hp}/  -H 'Host: tenant-b.local'  ->  HTTP $cb   body: $(printf '%s' "$b" | tr -d '\n')"
  echo "  http://127.0.0.1:${hp}/  -H 'Host: nope.local'      ->  HTTP $cn   (expect 404 — no route)"
  local pass=1
  { [ "$ca" = 200 ] && has "$a" TENANT-A-BACKEND; } || pass=0
  { [ "$cb" = 200 ] && has "$b" TENANT-B-BACKEND; } || pass=0
  [ "$pass" = 1 ] || die "ROUTABLE PROOF FAILED — see the responses above"
  ok "ROUTABLE: tenant-a.local & tenant-b.local each return 200 from their OWN backend, no token"
}

# ---- Phase 10 — SEC-3 Property 1: Kyverno admission (red-first) --------------
phase10_sec3_admission() {
  section "PHASE 10 — SEC-3 Property 1: Kyverno admission rejects open rules (red-first)"
  section "applying Kyverno guardrails (Enforce)"
  k apply -f "$REPO_ROOT/k8s/policies/disallow-open-intra-namespace-ingress.yaml"
  k apply -f "$REPO_ROOT/k8s/policies/disallow-public-backend-services.yaml"
  k wait --for=condition=Ready clusterpolicy/disallow-open-intra-namespace-ingress --timeout=120s 2>/dev/null || true
  k wait --for=condition=Ready clusterpolicy/disallow-public-backend-services   --timeout=120s 2>/dev/null || true

  # RED-A (required): an ingress `from` with an EMPTY podSelector ({}) = every pod
  # in the namespace — the exact lateral-movement hole. Must be DENIED at admission.
  local bad; bad="$(mktemp)"
  cat > "$bad" <<'NP'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: sec3-red-open-ingress, namespace: tenant-a }
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
NP
  section "RED — an open (podSelector {}) NetworkPolicy MUST be DENIED"
  local denied="" i=0 out
  while [ "$i" -lt 20 ]; do
    out="$(k apply -f "$bad" 2>&1 || true)"
    if has "$out" denied || has "$out" disallow-open-intra-namespace-ingress; then denied="$out"; break; fi
    k -n tenant-a delete networkpolicy sec3-red-open-ingress --ignore-not-found >/dev/null 2>&1 || true
    i=$((i + 1)); sleep 3
  done
  rm -f "$bad"
  [ -n "$denied" ] || die "guardrail NOT live: the open-podSelector NetworkPolicy was ADMITTED"
  echo "  Kyverno denial:"; printf '%s\n' "$denied" | fold -s -w 96 | sed 's/^/    /'
  ok "RED proven — Kyverno DENIED the open-podSelector NetworkPolicy"

  # RED-B (supporting): a NodePort backend Service bypasses the gateway → DENIED.
  local svc; svc="$(mktemp)"
  cat > "$svc" <<'SVC'
apiVersion: v1
kind: Service
metadata: { name: sec3-red-public, namespace: tenant-a }
spec:
  type: NodePort
  selector: { app: echo }
  ports: [{ port: 5678, targetPort: 5678 }]
SVC
  section "RED (supporting) — a NodePort backend Service MUST be DENIED"
  out="$(k apply -f "$svc" 2>&1 || true)"; rm -f "$svc"
  if has "$out" denied || has "$out" disallow-public-backend-services; then
    echo "  Kyverno denial:"; printf '%s\n' "$out" | fold -s -w 96 | sed 's/^/    /'
    ok "RED (supporting) proven — Kyverno DENIED the NodePort Service"
  else
    k -n tenant-a delete service sec3-red-public --ignore-not-found >/dev/null 2>&1 || true
    warn "NodePort not denied — continuing (the required NetworkPolicy guardrail is proven)"
  fi
  ok "Phase 10 (Property 1) verified"
}

# ---- Phase 11 — SEC-3 Property 2: Calico data-plane (red-first) --------------
phase11_sec3_dataplane() {
  section "PHASE 11 — SEC-3 Property 2: Calico drops the bypass hop, gateway allowed (red-first)"

  # NODE_CIDR = the kind docker network IPv4 subnet (the hostNetwork edge-proxy's
  # source). Take the IPv4 line only (kind also has an IPv6 subnet).
  local NODE_CIDR pfx
  NODE_CIDR="$(docker network inspect kind --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/' | head -1)"
  [ -n "$NODE_CIDR" ] || die "could not compute NODE_CIDR from docker network 'kind'"
  pfx="$(printf '%s' "$NODE_CIDR" | cut -d/ -f1 | cut -d. -f1-2)"
  log "NODE_CIDR=$NODE_CIDR  (/16 prefix '$pfx')  echo backend port=5678"

  section "verify edge-proxy node IPs fall INSIDE NODE_CIDR (else gateway-allow won't match)"
  local ip ok_nodes=1
  for ip in $(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{range .items[*]}{.status.hostIP}{"\n"}{end}' | sort -u); do
    if in_cidr16 "$pfx" "$ip"; then ok "edge-proxy node $ip ∈ $NODE_CIDR"; else warn "edge-proxy node $ip ∉ $NODE_CIDR"; ok_nodes=0; fi
  done
  [ "$ok_nodes" = 1 ] || die "an edge-proxy node IP is outside NODE_CIDR — the gateway-allow would not match"

  section "deploy attacker (pod-network pod, neutral ns)"
  if docker pull "$ATTACKER_IMAGE" >/dev/null 2>&1; then
    kind load docker-image --name "$CLUSTER_NAME" "$ATTACKER_IMAGE" >/dev/null 2>&1 || true
  else warn "attacker image not preloaded — node will pull at runtime"; fi
  k apply -f "$LOCAL_DIR/manifests/sec3-attacker.yaml"
  wait_rollout deploy/attacker sec3-attacker 120s
  local atk_ip
  atk_ip="$(k -n sec3-attacker get pod -l app=attacker -o jsonpath='{.items[0].status.podIP}')"
  [ -n "$atk_ip" ] || die "attacker pod has no IP"
  if in_cidr16 "$pfx" "$atk_ip"; then die "attacker IP $atk_ip is INSIDE NODE_CIDR — it would be allowed; proof invalid"; fi
  ok "attacker pod IP $atk_ip ∉ NODE_CIDR $NODE_CIDR — a genuine pod-network source"

  local ipA ipB
  ipA="$(k -n tenant-a get svc echo -o jsonpath='{.spec.clusterIP}')"
  ipB="$(k -n tenant-b get svc echo -o jsonpath='{.spec.clusterIP}')"
  log "tenant-a echo ClusterIP=$ipA:5678   tenant-b echo ClusterIP=$ipB:5678"

  # TRUE red baseline every run: remove any backend NetworkPolicies first.
  section "RED baseline — delete any existing backend NetworkPolicies"
  k -n tenant-a delete networkpolicy --all --ignore-not-found >/dev/null 2>&1 || true
  k -n tenant-b delete networkpolicy --all --ignore-not-found >/dev/null 2>&1 || true
  sleep 2

  section "RED — attacker → each backend DIRECTLY (gateway bypass) MUST succeed"
  local ra rb
  ra="$(attacker_get "$ipA" 5678)"; rb="$(attacker_get "$ipB" 5678)"
  echo "  attacker($atk_ip) -> tenant-a $ipA:5678  =>  $ra"
  echo "  attacker($atk_ip) -> tenant-b $ipB:5678  =>  $rb"
  { has "$ra" code=200 && has "$ra" TENANT-A-BACKEND; } || die "RED baseline broken: attacker couldn't reach tenant-a with no policy"
  { has "$rb" code=200 && has "$rb" TENANT-B-BACKEND; } || die "RED baseline broken: attacker couldn't reach tenant-b with no policy"
  ok "RED proven — with NO backend policy the bypass hop is OPEN (200 from each backend)"

  # Resolve the template locally (NOT by editing k8s/policies): backend-ns -> each
  # tenant, NODE_CIDR computed, ipBlock port = the REAL echo port 5678, intra-ns
  # from/ports block DROPPED (a bare echo has no legitimate intra-ns client).
  section "apply resolved backend policy (default-deny + allow ipBlock $NODE_CIDR:5678) to tenant-a, tenant-b"
  local ns
  for ns in tenant-a tenant-b; do
    k apply -f - <<NP
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-ingress, namespace: $ns, labels: { part-of: edge-local, sec3: "true" } }
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-from-gateway, namespace: $ns, labels: { part-of: edge-local, sec3: "true" } }
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - ipBlock: { cidr: $NODE_CIDR }
      ports:
        - { protocol: TCP, port: 5678 }
NP
  done
  ok "backend policy applied (also Property 1 GREEN: the ipBlock policy is ADMITTED, not denied)"
  sleep 3   # let Calico program the rules

  # Converge: default-deny programs a beat before allow-from-gateway, so the
  # gateway path can 503 briefly right after apply. Wait until BOTH the drop and
  # the allow hold, then assert them SEPARATELY below.
  section "GREEN — waiting for Calico to converge (attacker dropped AND gateway allowed)"
  local i=0 ga gb ca cb
  while [ "$i" -lt 20 ]; do
    ga="$(attacker_get "$ipA" 5678)"; gb="$(attacker_get "$ipB" 5678)"
    ca="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: tenant-a.local' http://127.0.0.1:443/ 2>/dev/null || true)"
    cb="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: tenant-b.local' http://127.0.0.1:443/ 2>/dev/null || true)"
    if has "$ga" code=000 && has "$gb" code=000 && [ "$ca" = 200 ] && [ "$cb" = 200 ]; then break; fi
    i=$((i + 1)); sleep 2
  done

  # (a) the bypass DROP — proven on its own.
  section "GREEN (a) — attacker bypass DROPPED (flip from the RED success)"
  echo "  attacker($atk_ip) -> tenant-a $ipA:5678  =>  $ga"
  echo "  attacker($atk_ip) -> tenant-b $ipB:5678  =>  $gb"
  has "$ga" code=000 || die "tenant-a bypass NOT dropped (expected timeout) — got: $ga"
  has "$gb" code=000 || die "tenant-b bypass NOT dropped (expected timeout) — got: $gb"
  ok "GREEN DROP proven — the cross-tenant bypass FLIPPED 200 -> dropped for BOTH tenants"

  # (b) the gateway path preserved — a SEPARATE assertion (never combined with the drop).
  section "GREEN (b) — gateway path (node :443) still ALLOWED"
  local ba bb
  ba="$(curl -s --max-time 6 -H 'Host: tenant-a.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  bb="$(curl -s --max-time 6 -H 'Host: tenant-b.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  echo "  gateway :443 Host tenant-a.local => HTTP $ca  $ba"
  echo "  gateway :443 Host tenant-b.local => HTTP $cb  $bb"
  { [ "$ca" = 200 ] && has "$ba" TENANT-A-BACKEND; } || die "gateway path to tenant-a BROKE under the policy (HTTP $ca)"
  { [ "$cb" = 200 ] && has "$bb" TENANT-B-BACKEND; } || die "gateway path to tenant-b BROKE under the policy (HTTP $cb)"
  ok "GREEN ALLOW proven — gateway :443 still 200 from each backend (source node IP ∈ NODE_CIDR, allowed on :5678)"

  section "confirm echo pods stay Ready under the policy (kubelet probes ride the node IP)"
  k -n tenant-a rollout status deploy/echo --timeout=40s
  k -n tenant-b rollout status deploy/echo --timeout=40s
  ok "Phase 11 (Property 2) verified"
}

# ---- Phase 12 — CFG-1 flip + ext_authz LIVE (four properties, red-first) -----
# helm_set_extauthz <true|false> — flip ext_authz LIVE via --set. The chart
# default is on (phase 7 installs it so); phase 12 switches it off to prove the
# CFG-1 guard, then back on. helm only rolls the control-plane when the value
# actually changes.
helm_set_extauthz() {
  section "helm: ext_authz enabled=$1 (LIVE --set flip)"
  h upgrade edge-control-plane "$REPO_ROOT/deploy/helm/edge-control-plane" -n "$INFRA_NS" \
    -f "$LOCAL_DIR/values/values-control-plane.yaml" \
    --set extAuthz.enabled="$1" --wait --timeout 200s
  # The control-plane's snapshot version counter is per-process (non-HA), so it
  # RESETS to v1 when the control-plane rolls on a flip. A still-connected
  # edge-proxy that holds a higher version then rejects the new push as stale
  # (cds/lds update_failure; the config silently never applies). A FRESH
  # edge-proxy connection has no prior version and applies it cleanly — so roll
  # edge-proxy after every flip.
  section "roll edge-proxy for a fresh xDS connection (avoid the version-reset collision)"
  k -n edge rollout restart ds/edge-proxy >/dev/null
  k -n edge rollout status ds/edge-proxy --timeout=120s
}

# seed_secure_route / drop_secure_route — the secure.local (auth_policy='jwt')
# route -> whoami, mirroring phase8's direct SQL. $1 = whoami ClusterIP (seed only).
drop_secure_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<'SQL' >/dev/null
DELETE FROM routes    WHERE name='secure-whoami';
DELETE FROM endpoints WHERE cluster_id='secure-whoami';
DELETE FROM clusters  WHERE name='secure-whoami';
SQL
}
seed_secure_route() {
  local wip="$1" pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<SQL >/dev/null
INSERT INTO clusters (id,name) VALUES ('secure-whoami','secure-whoami') ON CONFLICT (name) DO NOTHING;
DELETE FROM endpoints WHERE cluster_id='secure-whoami';
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('secure-whoami-0','secure-whoami','${wip}',80,1);
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('secure-whoami','secure-whoami','local-gw',ARRAY['secure.local']::text[],'/','secure-whoami',30,'jwt',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,timeout_seconds=EXCLUDED.timeout_seconds,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;
SQL
}

phase12_extauthz_cutover() {
  section "PHASE 12 — CFG-1 flip + ext_authz LIVE (four properties, red-first)"
  local AUD="edge-gateway"   # issuer ISSUER_AUDIENCE == auth-service JWT_AUDIENCE (Phase 5)
  local ISS="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"  # iss == JWT_ISSUER

  # ---- reset to a clean PRE-FLIP state (idempotent re-runs) ----
  section "reset — remove secure.local + ensure ext_authz OFF (safe: no jwt route present)"
  drop_secure_route
  helm_set_extauthz false
  retry 20 2 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -H 'Host: tenant-a.local' http://127.0.0.1:443/)\" = 200 ]" \
    && ok "pre-flip baseline serving (ext_authz OFF, none-routes up)" || die "pre-flip baseline not serving"

  # ---- PREREQ GATE — the deny-all trap (flip ONLY if BOTH pass) ----
  section "PREREQ GATE — deny-all-trap (flip only if BOTH pass, else STOP)"
  k -n "$INFRA_NS" wait --for=condition=Available deploy/auth-service --timeout=60s >/dev/null 2>&1 \
    || die "PREREQ FAIL: auth-service not Available (JWKS-at-boot would have failed it)"
  local eps; eps="$(k -n "$INFRA_NS" get endpoints auth-service -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)"
  [ -n "$eps" ] || die "PREREQ FAIL: auth-service Service has no ready endpoints (:50051 unreachable)"
  ok "(1) auth-service Ready + endpoints [$eps]; Ready ⇒ JWKS-at-boot succeeded (it fails to boot otherwise)"
  k -n edge exec "$(ep_pod)" -- ls -l /etc/authz-client-tls/ca.crt >/dev/null 2>&1 \
    && ok "(2) edge-proxy has /etc/authz-client-tls/ca.crt mounted (mTLS caFile present)" \
    || die "PREREQ FAIL: edge-proxy lacks /etc/authz-client-tls/ca.crt — flipping renders plaintext ⇒ deny-all"

  # ---- header-reflecting backend ----
  section "deploy whoami (header-reflecting backend for secure.local)"
  if docker pull "$WHOAMI_IMAGE" >/dev/null 2>&1; then kind load docker-image --name "$CLUSTER_NAME" "$WHOAMI_IMAGE" >/dev/null 2>&1 || true; fi
  k apply -f "$LOCAL_DIR/manifests/secure-backend.yaml"
  wait_rollout deploy/whoami tenant-secure 120s
  local wip; wip="$(k -n tenant-secure get svc whoami -o jsonpath='{.spec.clusterIP}')"
  [ -n "$wip" ] || die "whoami ClusterIP unresolved"
  log "whoami ClusterIP=$wip:80"

  # ================= PROPERTY 4 — CFG-1 config-time guard (red-first, BEFORE flip) ==========
  section "PROPERTY 4 (red-first) — CFG-1 guard REFUSES the jwt route while ext_authz OFF"
  local before_ver; before_ver="$(envoy_config_dump "$(ep_pod)" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "Envoy route-config version(s) BEFORE seeding secure.local: ${before_ver:-<none>}"
  seed_secure_route "$wip"
  sleep 10   # reconciler polls every ~5s; let it hit the guard
  echo "  control-plane refusal log:"
  k -n "$INFRA_NS" logs deploy/edge-control-plane --tail=80 2>/dev/null \
    | grep -aiE 'refusing to build snapshot|auth_policy != none' | tail -2 | sed 's/^/    /' \
    || die "P4 FAIL: no control-plane refusal log — the guard did not fire"
  local dump after_ver
  dump="$(envoy_config_dump "$(ep_pod)")"
  after_ver="$(printf '%s' "$dump" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "Envoy route-config version(s) AFTER: ${after_ver:-<none>}"
  has "$dump" secure.local && die "P4 FAIL: secure.local present in Envoy — an auth-wanting route is served OPEN"
  [ "$before_ver" = "$after_ver" ] && ok "Envoy snapshot version did NOT advance (${after_ver})" \
    || warn "route-config version changed ($before_ver -> $after_ver) — but secure.local absent (below)"
  local p4c; p4c="$(gw_code secure.local)"
  [ "$p4c" != 200 ] || die "P4 FAIL: secure.local served 200 while ext_authz OFF (open identity listener)"
  ok "P4 GREEN — control-plane refused; secure.local ABSENT from Envoy + not served ($p4c); tenant-a still $(gw_code tenant-a.local) (last-good retained)"

  # ================= THE FLIP ==========
  section "THE FLIP — ext_authz ON (live)"
  helm_set_extauthz true
  # Wait until it is published AND gated on the gateway that serves :443 (no
  # token => 401), and assert on that same result: edge-proxy has just rolled, so
  # a second, separate dump can land on the other pod before its snapshot does.
  local i=0 flipped=0
  while [ "$i" -lt 25 ]; do
    if has "$(envoy_config_dump "$(ep_pod)")" secure.local && [ "$(gw_code secure.local)" = 401 ]; then flipped=1; break; fi
    i=$((i + 1)); sleep 2
  done
  [ "$flipped" = 1 ] || die "FLIP FAIL: secure.local not published (and gated, 401 without a token) after enabling ext_authz"
  ok "FLIP done — ext_authz ON; secure.local published (now gated by ext_authz)"

  # ================= PROPERTY 1 — valid JWT -> 200 + trusted injection (red-first) ==========
  section "PROPERTY 1 (red-first) — valid JWT → 200 + TRUSTED header injection"
  local UMAIL="dev@edge.local" UPASS="devpassword-abc12345"
  k -n "$INFRA_NS" exec deploy/edge-issuer -- /issuer adduser --email "$UMAIL" --password "$UPASS" --team eng >/dev/null 2>&1 \
    && log "created issuer user $UMAIL" || log "issuer user $UMAIL already exists (adduser idempotent)"
  # Mint from the in-cluster OpenSSL curl pod (macOS system curl is LibreSSL and
  # cannot handshake the issuer). Reaches edge-issuer.infra directly over TLS.
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=60s >/dev/null 2>&1 || true
  local TOK="" mi=0
  while [ "$mi" -lt 10 ]; do
    TOK="$(k -n tenant-secure exec minter -- curl -sk --max-time 6 -X POST \
      "https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081/login" \
      -H 'Content-Type: application/json' -d "{\"email\":\"$UMAIL\",\"password\":\"$UPASS\"}" 2>/dev/null \
      | jq -r '.access_token // empty' 2>/dev/null || true)"
    { [ -n "$TOK" ] && [ "$TOK" != null ]; } && break
    mi=$((mi + 1)); sleep 2
  done
  { [ -n "$TOK" ] && [ "$TOK" != null ]; } || die "P1 FAIL: could not mint a JWT via POST /login"
  ok "minted a real JWT via /login (aud=$AUD iss=$ISS; token len ${#TOK})"

  local c1 b1
  c1="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
  b1="$(gw_body secure.local -H "Authorization: Bearer $TOK")"
  [ "$c1" = 200 ] || die "P1 FAIL: valid JWT did not yield 200 (got $c1)"
  local low; low="$(printf '%s' "$b1" | tr 'A-Z' 'a-z')"
  local hdr
  for hdr in x-user-id x-user-email x-auth-iss x-gateway-auth; do
    has "$low" "$hdr" || die "P1 FAIL: injected header '$hdr' absent from whoami reflection"
  done
  has "$low" "$UMAIL" || die "P1 FAIL: whoami did not reflect the JWT-derived email $UMAIL"
  echo "  secure.local + valid JWT -> HTTP $c1; whoami reflected injected headers:"
  printf '%s\n' "$b1" | grep -iE 'X-User-Id|X-User-Teams|X-User-Email|X-Auth-Iss|X-Gateway-Auth' | sed 's/^/    /'
  ok "P1 GREEN — 200 + x-user-id/x-user-email/x-auth-iss/x-gateway-auth injected (JWT-derived)"

  section "P1 transit — x-gateway-auth is a signed, short-lived assertion for THIS request"
  local ga ah ap as tdir jwks claims
  ga="$(printf '%s\n' "$b1" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-gateway-auth"{print $2; exit}')"
  IFS=. read -r ah ap as <<<"$ga"
  [ -n "$as" ] || die "P1 FAIL: x-gateway-auth is not a signed assertion (got '${ga:0:40}')"
  [ "$(b64url_d "$ah" | jq -r .alg)" = EdDSA ] || die "P1 FAIL: assertion is not EdDSA-signed"
  claims="$(b64url_d "$ap")"
  printf '%s' "$claims" | jq -e --arg e "$UMAIL" \
    '.amr == "jwt" and .email == $e and .htm == "GET" and .htu == "secure.local/" and (.exp - .iat) == 30 and (.jti | length) > 0' >/dev/null \
    || die "P1 FAIL: assertion claims do not name this request and user: $claims"
  # The public key a backend verifies with, as auth-service publishes it.
  kubectl --context "$KUBE_CONTEXT" -n "$INFRA_NS" port-forward deploy/auth-service 19090:9090 >/dev/null 2>&1 &
  local pf=$!; sleep 4
  jwks="$(curl -s --max-time 6 http://127.0.0.1:19090/.well-known/transit-jwks.json 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  [ "$(printf '%s' "$jwks" | jq -r '.keys[0].kid')" = "$(b64url_d "$ah" | jq -r .kid)" ] \
    || die "P1 FAIL: /.well-known/transit-jwks.json does not publish the assertion's kid (got: ${jwks:-nothing})"
  # Rebuild a PEM from the published x (SPKI prefix for Ed25519 + 32 raw bytes)
  # and check the signature with it — exactly what a backend does.
  tdir="$(mktemp -d)"
  { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; b64url_d "$(printf '%s' "$jwks" | jq -r '.keys[0].x')"; } > "$tdir/pub.der"
  openssl pkey -pubin -inform DER -in "$tdir/pub.der" -out "$tdir/pub.pem" 2>/dev/null
  printf '%s' "$ah.$ap" > "$tdir/msg"; b64url_d "$as" > "$tdir/sig"
  openssl pkeyutl -verify -pubin -inkey "$tdir/pub.pem" -rawin -in "$tdir/msg" -sigfile "$tdir/sig" >/dev/null 2>&1 \
    || die "P1 FAIL: the assertion's signature does not verify against the published transit key"
  printf '%s' "$ah.${ap}x" > "$tdir/msg"
  openssl pkeyutl -verify -pubin -inkey "$tdir/pub.pem" -rawin -in "$tdir/msg" -sigfile "$tdir/sig" >/dev/null 2>&1 \
    && die "P1 FAIL: a tampered assertion still verified — the signature check is not checking"
  rm -rf "$tdir"
  echo "  x-gateway-auth claims: $(printf '%s' "$claims" | jq -c '{sub,amr,email,htm,htu,ttl:(.exp-.iat)}')"
  ok "P1 transit GREEN — x-gateway-auth is an EdDSA assertion for GET secure.local/ and $UMAIL, 30s, verified with the published key"

  section "P1 anti-spoof — a client-forged x-user-email MUST be overwritten"
  local bsp lsp
  bsp="$(gw_body secure.local -H "Authorization: Bearer $TOK" -H 'x-user-email: attacker@evil.com')"
  lsp="$(printf '%s' "$bsp" | tr 'A-Z' 'a-z')"
  has "$lsp" 'attacker@evil.com' && die "P1 FAIL: forged x-user-email SURVIVED (client value not overwritten)"
  has "$lsp" "$UMAIL" || die "P1 FAIL: JWT email missing after the spoof attempt"
  echo "  forged 'x-user-email: attacker@evil.com' -> whoami shows: $(printf '%s' "$bsp" | grep -iE 'X-User-Email' | head -1 | sed 's/^ *//')"
  ok "P1 anti-spoof GREEN — whoami shows the JWT email ($UMAIL); the forged attacker@evil.com was stripped"

  local cc; cc="$(gw_code tenant-a.local)"
  [ "$cc" = 200 ] || die "P1 FAIL: control tenant-a.local (none) not 200 (got $cc)"
  ok "P1 control — tenant-a.local (auth_policy=none) with NO token still 200"

  # ================= PROPERTY 2 — no/invalid JWT -> 401 (red-first) ==========
  section "PROPERTY 2 (red-first) — no / invalid JWT → 401"
  local c_none c_garbage
  c_none="$(gw_code secure.local)"
  c_garbage="$(gw_code secure.local -H 'Authorization: Bearer not-a-jwt')"
  echo "  secure.local, no Authorization -> HTTP $c_none"
  echo "  secure.local, garbage token    -> HTTP $c_garbage"
  [ "$c_none" = 401 ]    || die "P2 FAIL: no-token got $c_none (expected 401)"
  [ "$c_garbage" = 401 ] || die "P2 FAIL: garbage token got $c_garbage (expected 401)"
  ok "P2 GREEN — secure.local without a valid JWT → 401 (no-token AND garbage)"

  # ================= PROPERTY 3 — auth-service down -> fail-closed deny (red-first) ==========
  section "PROPERTY 3 (red-first) — auth-service DOWN → fail-closed deny (failure_mode_allow:false)"
  k -n "$INFRA_NS" scale deploy/auth-service --replicas=0 >/dev/null
  k -n "$INFRA_NS" wait --for=delete pod -l app.kubernetes.io/name=auth-service --timeout=60s >/dev/null 2>&1 || true
  sleep 3
  local c_down; c_down="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
  echo "  secure.local + VALID JWT, auth-service DOWN -> HTTP $c_down"
  [ "$c_down" != 200 ] || die "P3 FAIL: served 200 with auth-service DOWN — this would be fail-OPEN"
  ok "P3 GREEN — with auth-service down, even a VALID JWT is DENIED ($c_down), never served (fail-closed)"

  section "P3 recovery — scale auth-service back to 1"
  k -n "$INFRA_NS" scale deploy/auth-service --replicas=1 >/dev/null
  k -n "$INFRA_NS" rollout status deploy/auth-service --timeout=120s
  local j=0 c_rec
  while [ "$j" -lt 25 ]; do c_rec="$(gw_code secure.local -H "Authorization: Bearer $TOK")"; [ "$c_rec" = 200 ] && break; j=$((j + 1)); sleep 2; done
  echo "  secure.local + VALID JWT, auth-service back -> HTTP $c_rec"
  [ "$c_rec" = 200 ] || die "P3 FAIL: did not recover to 200 after auth-service returned (got $c_rec)"
  ok "P3 recovery — auth-service back → secure.local + valid JWT → 200 again"

  section "Phase 12 end state — ext_authz ON, secure.local(jwt) + tenant-a/b(none) all serving"
  echo "    secure.local (jwt, valid token) -> HTTP $(gw_code secure.local -H "Authorization: Bearer $TOK")"
  echo "    tenant-a.local (none, no token) -> HTTP $(gw_code tenant-a.local)"
  echo "    tenant-b.local (none, no token) -> HTTP $(gw_code tenant-b.local)"
  ok "Phase 12 (all four ext_authz properties) verified"
}

# ---- Phase 13 — R8 fail-static inconsistent-snapshot guard (live) -----------
# drop_ghost_route removes the injected dangling route (idempotent).
drop_ghost_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 \
    -c "DELETE FROM routes WHERE name='r8-ghost';" >/dev/null
}

phase13_inconsistent_guard() {
  section "PHASE 13 — R8 fail-static inconsistent-snapshot guard (live, red-first)"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  drop_ghost_route   # clean any prior injection (idempotent)

  # RED baseline: a HEALTHY snapshot is serving (last-good exists); capture Envoy's
  # route-config version so we can prove it does NOT advance.
  section "RED baseline — tenant-a/b serve 200; capture Envoy route-config version"
  local ca cb; ca="$(gw_code tenant-a.local)"; cb="$(gw_code tenant-b.local)"
  { [ "$ca" = 200 ] && [ "$cb" = 200 ]; } || die "R8 baseline broken: tenant-a/b not both 200 ($ca/$cb)"
  local before_ver; before_ver="$(envoy_config_dump "$(ep_pod)" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "tenant-a=$ca tenant-b=$cb ; Envoy route-config version BEFORE: ${before_ver:-<none>}"

  # Inject the inconsistency the guard reliably catches AND the data path can
  # produce: a route -> a cluster with NO clusters row (dangling RDS->CDS, which
  # Envoy's Consistent() misses but the widened R8 check blocks). auth_policy='none'
  # so CFG-1 does NOT also fire. Injected AFTER a healthy snapshot exists.
  section "inject a dangling route (r8-ghost -> a nonexistent cluster) via the data path"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<'SQL' >/dev/null
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('r8-ghost','r8-ghost','local-gw',ARRAY['r8-ghost.local']::text[],'/','r8-ghost-cluster-absent',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,deleted_at=NULL,updated_at=now();
SQL
  sleep 10   # let the reconciler poll (~5s) + hit the guard

  # GREEN (fail-static, LIVE): the control-plane REFUSED — its log carries the
  # refusal + blocked_total (the InconsistentSnapshotsBlocked counter); Envoy's
  # route-config version did not advance; the bad route is ABSENT from Envoy;
  # tenant-a/b STILL serve 200.
  section "GREEN — control-plane REFUSED; last-good retained"
  echo "  control-plane refusal log (carries blocked_total = the counter):"
  k -n "$INFRA_NS" logs deploy/edge-control-plane --tail=120 2>/dev/null \
    | grep -aiE 'refusing to publish inconsistent snapshot|absent from CDS|blocked_total' | tail -1 | sed 's/^/    /' \
    || die "R8 FAIL: no 'refusing to publish inconsistent snapshot' log — the guard did not fire (control-plane lacks the R8 widening?)"
  local dump after_ver
  dump="$(envoy_config_dump "$(ep_pod)")"
  after_ver="$(printf '%s' "$dump" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "Envoy route-config version AFTER: ${after_ver:-<none>}"
  has "$dump" r8-ghost && die "R8 FAIL: the dangling route r8-ghost IS in Envoy — the inconsistent snapshot was published"
  [ "$before_ver" = "$after_ver" ] && ok "Envoy route-config version did NOT advance ($after_ver)" \
    || warn "route-config version changed ($before_ver -> $after_ver) — but r8-ghost is absent (asserted above)"
  local ca2 cb2; ca2="$(gw_code tenant-a.local)"; cb2="$(gw_code tenant-b.local)"
  { [ "$ca2" = 200 ] && [ "$cb2" = 200 ]; } || die "R8 FAIL: tenant-a/b broke under the inconsistent snapshot ($ca2/$cb2)"
  ok "GREEN — r8-ghost ABSENT from Envoy; version unchanged; tenant-a=$ca2 tenant-b=$cb2 (last-good served)"

  # Clean up so the phase leaves a consistent, re-runnable state.
  section "cleanup — remove the dangling route; confirm the reconciler resumes"
  drop_ghost_route
  local i=0
  while [ "$i" -lt 15 ]; do [ "$(gw_code tenant-a.local)" = 200 ] && break; i=$((i + 1)); sleep 2; done
  ok "Phase 13 (R8 inconsistent guard) verified — cleaned up; tenant-a/b serving"
}

# ---- Phase 14 — fail-static guard counters exported as metrics (live) --------
# inject_ghost_route inserts the dangling route (r8-ghost -> a nonexistent
# cluster) via the data path so the reconciler's inconsistent-snapshot guard
# trips. Same injection phase 13 uses; paired with drop_ghost_route.
inject_ghost_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<'SQL' >/dev/null
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('r8-ghost','r8-ghost','local-gw',ARRAY['r8-ghost.local']::text[],'/','r8-ghost-cluster-absent',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,deleted_at=NULL,updated_at=now();
SQL
}

# cp_scrape — the control-plane's /metrics text (fail-static guard counters) via a
# short-lived port-forward to :2112 (the port the edge-control-plane chart declares
# and Prometheus scrapes). Plain HTTP, so host curl (macOS LibreSSL) is fine.
# Port-forward routes through the API server, so SEC-3 NetworkPolicies don't apply.
# Echoes the exposition; empty on failure.
cp_scrape() {
  local lp="${CP_METRICS_LP:-12112}" pid out i=0
  k -n "$INFRA_NS" port-forward deploy/edge-control-plane "${lp}:2112" >/dev/null 2>&1 &
  pid=$!
  while [ "$i" -lt 20 ]; do
    out="$(curl -s --max-time 4 "http://127.0.0.1:${lp}/metrics" 2>/dev/null || true)"
    [ -n "$out" ] && break
    i=$((i + 1)); sleep 1
  done
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
  printf '%s' "$out"
}

# blocked_of <metrics-text> <reason> — value of the
# xds_snapshots_blocked_total{reason="<reason>"} series in the given exposition
# (empty if the series is absent). The {reason=...} match skips the # HELP/# TYPE
# lines, and the tiny doc makes the pipe SIGPIPE-safe.
blocked_of() {
  printf '%s\n' "$1" | grep -F "xds_snapshots_blocked_total{reason=\"$2\"}" | awk '{print $NF}' | tail -1
}

phase14_failstatic_metrics() {
  section "PHASE 14 — fail-static guard counters exported as metrics (live, red-first)"
  drop_ghost_route   # clean slate

  # The metrics endpoint must be LIVE on :2112 — before this change nothing bound
  # it, so the chart's already-configured Prometheus scrape got connection-refused.
  section "scrape the control-plane /metrics on :2112 (the chart's declared scrape target)"
  local m0; m0="$(cp_scrape)"
  [ -n "$m0" ] || die "PHASE14 FAIL: /metrics on :2112 returned nothing — the metrics server is not serving (connection refused?)"
  has "$m0" "xds_snapshots_blocked_total" || die "PHASE14 FAIL: xds_snapshots_blocked_total absent from the live /metrics"
  echo "  live fail-static series:"; printf '%s\n' "$m0" | grep -F "xds_snapshots_blocked_total{" | sed 's/^/    /'

  # RED baseline: capture the inconsistent-reason counter on the running process.
  local before; before="$(blocked_of "$m0" inconsistent)"
  [ -n "$before" ] || die "PHASE14 FAIL: the inconsistent series is absent (it must exist from t=0)"
  log "baseline  xds_snapshots_blocked_total{reason=\"inconsistent\"} = $before"

  # Trip the guard on the ACTUAL control-plane: inject a dangling route
  # (auth_policy=none so CFG-1 does not also fire). The reconciler withholds the
  # publish and increments the counter each poll while it is present.
  section "inject a dangling route (r8-ghost -> absent cluster) to trip the guard"
  inject_ghost_route
  sleep 10   # reconciler poll (~5s) + guard trip

  # GREEN: the exported counter ROSE on the live control-plane.
  section "GREEN — the exported counter ROSE (prod can alert on this)"
  local m1 after; m1="$(cp_scrape)"; after="$(blocked_of "$m1" inconsistent)"
  [ -n "$after" ] || die "PHASE14 FAIL: could not read the inconsistent counter after injection"
  log "after     xds_snapshots_blocked_total{reason=\"inconsistent\"} = $after"
  awk -v a="$before" -v b="$after" 'BEGIN{exit !(b>a)}' \
    || { drop_ghost_route; die "PHASE14 FAIL: the inconsistent counter did NOT rise ($before -> $after) — the metric is not wired to the guard"; }
  ok "GREEN — xds_snapshots_blocked_total{reason=\"inconsistent\"} rose $before -> $after on the live control-plane"

  # Cleanup so the phase leaves a consistent, re-runnable state.
  section "cleanup — remove the dangling route; confirm serving resumes"
  drop_ghost_route
  local i=0
  while [ "$i" -lt 15 ]; do [ "$(gw_code tenant-a.local)" = 200 ] && break; i=$((i + 1)); sleep 2; done
  ok "Phase 14 (fail-static metrics) verified — cleaned up; tenant-a/b serving"
}

# ---- Phase 15 — the OSB broker answers, and its provision is served ---------
# The tenant key the broker resolves to team 'e2e' (stored hashed, as in prod).
OSB_KEY="${OSB_KEY:-local-e2e-osb-tenant-key-0123456789}"
OSB_TEAM="e2e"
OSB_SERVICE="e2e-stub"

# osb_register_tenant — the 'e2e' tenant API key, stored as its SHA-256 (as in
# prod, never in the clear). Idempotent.
osb_register_tenant() {
  section "register the 'e2e' tenant API key (stored as its SHA-256, never in the clear)"
  local pgpod kh
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  kh="$(printf '%s' "$OSB_KEY" | openssl dgst -sha256 -r | cut -d' ' -f1)"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -c \
    "INSERT INTO tenant_api_keys (key_hash, team) VALUES ('$kh', '$OSB_TEAM') ON CONFLICT (key_hash) DO UPDATE SET team = EXCLUDED.team;" >/dev/null
  ok "tenant key registered for team '$OSB_TEAM'"
}

# osb_call <METHOD> <path> [json-body] — call the broker API (plain HTTP in the
# cluster) through a short-lived port-forward, as the 'e2e' tenant. Echoes
# "<http_code> <body>"; the code is 000 if the broker never answered.
osb_call() {
  local m="$1" path="$2" data="${3:-}" lp="${OSB_LP:-18080}" pid out code=000 i=0
  k -n "$INFRA_NS" port-forward svc/edge-osb "${lp}:8080" >/dev/null 2>&1 &
  pid=$!
  while [ "$i" -lt 20 ]; do
    if [ -n "$data" ]; then
      out="$(curl -s --max-time 6 -w '\n%{http_code}' -X "$m" -H "Authorization: Bearer $OSB_KEY" \
        -H 'Content-Type: application/json' -d "$data" "http://127.0.0.1:${lp}${path}" 2>/dev/null || true)"
    else
      out="$(curl -s --max-time 6 -w '\n%{http_code}' -X "$m" -H "Authorization: Bearer $OSB_KEY" \
        "http://127.0.0.1:${lp}${path}" 2>/dev/null || true)"
    fi
    code="$(printf '%s\n' "$out" | tail -1)"
    [ -n "$code" ] && [ "$code" != 000 ] && break
    i=$((i + 1)); sleep 1
  done
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
  printf '%s %s' "${code:-000}" "$(printf '%s\n' "$out" | sed '$d')"
}

# osb_wait_completed <request_id> — poll the broker until the worker has applied
# the request (COMPLETED); dies on FAILED or after ~90s.
osb_wait_completed() {
  local rid="$1" i=0 r st=""
  while [ "$i" -lt 45 ]; do
    r="$(osb_call GET "/v1/requests/$rid")"
    st="$(printf '%s' "${r#* }" | jq -r '.status // empty' 2>/dev/null || true)"
    case "$st" in
      COMPLETED) ok "request $rid COMPLETED by the OSB worker"; return 0 ;;
      FAILED) die "PHASE15 FAIL: request $rid FAILED — $(printf '%s' "${r#* }" | jq -r '.error // empty')" ;;
    esac
    i=$((i + 1)); sleep 2
  done
  die "PHASE15 FAIL: request $rid never completed (last status '${st:-<none>}', last answer: $r)"
}

# gw80_code / gw80_body <host> [curl args...] — a request through the gateway's
# shared HTTP listener (node :80), where OSB-provisioned HTTP services land.
gw80_code() { local host="$1"; shift; curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H "Host: $host" "$@" http://127.0.0.1:80/ 2>/dev/null || true; }
gw80_body() { local host="$1"; shift; curl -s --max-time 6 -H "Host: $host" "$@" http://127.0.0.1:80/ 2>/dev/null || true; }

phase15_osb_broker() {
  section "PHASE 15 — the OSB broker answers; a service it provisions is served through Envoy"
  osb_register_tenant

  section "deploy the stub upstream (osb-stub/echo -> OSB-PROVISIONED-BACKEND)"
  k apply -f "$LOCAL_DIR/manifests/osb-stub.yaml"
  wait_rollout deploy/echo osb-stub 120s
  local sip; sip="$(k -n osb-stub get svc echo -o jsonpath='{.spec.clusterIP}')"
  [ -n "$sip" ] || die "osb-stub echo ClusterIP unresolved"
  log "stub upstream ClusterIP=$sip:5678 (also the Host the provisioned route matches)"

  section "the broker answers — GET /healthz"
  local r; r="$(osb_call GET /healthz)"
  echo "  GET /healthz -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 200 ] && has "$r" '"ok":true' || die "PHASE15 FAIL: the broker did not answer /healthz (got: $r)"
  ok "edge-osb answers"

  # Clean slate for re-runs: a prior run may have left the service provisioned.
  r="$(osb_call DELETE "/v1/services/$OSB_SERVICE")"
  if [ "${r%% *}" = 202 ]; then
    log "removing a leftover '$OSB_SERVICE' from a prior run"
    osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  fi

  section "RED — before provisioning, Host $sip is NOT served on :80"
  local c0; c0="$(gw80_code "$sip")"
  echo "  :80 Host $sip -> HTTP $c0"
  [ "$c0" != 200 ] || die "PHASE15 FAIL: Host $sip already served 200 before the broker provisioned it — the proof would be vacuous"
  ok "RED proven — not served ($c0)"

  section "POST /v1/services — provision '$OSB_SERVICE' (HTTP, auth_policy=none) -> the stub"
  r="$(osb_call POST /v1/services \
    "{\"name\":\"$OSB_SERVICE\",\"team\":\"$OSB_TEAM\",\"host\":\"$sip\",\"port\":5678,\"protocol\":\"HTTP\",\"auth_policy\":\"none\"}")"
  echo "  POST /v1/services -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 202 ] || die "PHASE15 FAIL: provision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"

  section "GREEN — the provisioned service is served through Envoy on :80"
  local i=0 c1="" b1=""
  while [ "$i" -lt 30 ]; do
    c1="$(gw80_code "$sip")"
    [ "$c1" = 200 ] && break
    i=$((i + 1)); sleep 2
  done
  b1="$(gw80_body "$sip")"
  echo "  :80 Host $sip -> HTTP $c1  body: $(printf '%s' "$b1" | tr -d '\n')"
  { [ "$c1" = 200 ] && has "$b1" OSB-PROVISIONED-BACKEND; } \
    || die "PHASE15 FAIL: the provisioned service is not served by the stub through Envoy (HTTP $c1)"
  has "$(envoy_config_dump "$(ep_pod)")" "osb-${OSB_TEAM}-${OSB_SERVICE}" \
    || die "PHASE15 FAIL: Envoy has no osb-${OSB_TEAM}-${OSB_SERVICE} cluster/route"
  ok "GREEN — broker -> NATS -> worker -> Postgres -> control-plane -> xDS -> Envoy -> stub: 200 OSB-PROVISIONED-BACKEND"

  section "DELETE /v1/services/$OSB_SERVICE — deprovision, and the route goes away"
  r="$(osb_call DELETE "/v1/services/$OSB_SERVICE")"
  echo "  DELETE /v1/services/$OSB_SERVICE -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 202 ] || die "PHASE15 FAIL: deprovision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  i=0
  local c2=""
  while [ "$i" -lt 30 ]; do
    c2="$(gw80_code "$sip")"
    [ "$c2" != 200 ] && break
    i=$((i + 1)); sleep 2
  done
  echo "  :80 Host $sip -> HTTP $c2"
  [ "$c2" != 200 ] || die "PHASE15 FAIL: still served 200 after deprovision"
  ok "Phase 15 (OSB broker) verified — provisioned, served, deprovisioned"
}

# ---- Phase 16 — each node gets only its own tenant's TLS keys (XDS-1) ---------
# ep_pod_on <node> — the edge-proxy pod scheduled on that node.
ep_pod_on() { k -n edge get pod -l app.kubernetes.io/name=edge-proxy --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }

# node_secrets <node> — the SDS secret names that node's Envoy holds, one per line.
node_secrets() {
  envoy_config_dump "$(ep_pod_on "$1")" | jq -r '.configs[]?.dynamic_active_secrets[]?.name' 2>/dev/null | sort -u
}

# tls_get <node-ip> <host> — HTTPS to that node's :8443 with SNI and Host <host>,
# from inside the kind network (macOS cannot reach a node IP); curl -v output.
tls_get() {
  docker exec "${CLUSTER_NAME}-control-plane" curl -skv --max-time 6 \
    --resolve "$2:8443:$1" -H "Host: $2" "https://$2:8443/" 2>&1 || true
}

phase16_sds_scope() {
  section "PHASE 16 — two nodes serve two tenants; each node's SDS holds only its own tenant's key"
  local nodes nodeA nodeB ipA ipB pgpod tmp
  nodes="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u)"
  [ "$(printf '%s\n' "$nodes" | grep -c .)" = 2 ] || die "need edge-proxy on exactly two nodes, found: $(echo $nodes)"
  nodeA="$(printf '%s\n' "$nodes" | sed -n 1p)"; nodeB="$(printf '%s\n' "$nodes" | sed -n 2p)"
  ipA="$(k get node "$nodeA" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  ipB="$(k get node "$nodeB" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  log "tenant-a pinned to $nodeA ($ipA), tenant-b pinned to $nodeB ($ipB)"

  section "seed a cert per tenant and an HTTPS :8443 gateway per tenant presenting it, pinned by node_selector"
  # The keys go in as plaintext PEM, which the control plane reads as-is beside
  # sealed ones (the custodian seals at rest); what this phase measures is which
  # node the decrypted key is shipped to.
  tmp="$(mktemp -d)"
  local t sql=""
  for t in a b; do
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=tenant-$t.local" \
      -keyout "$tmp/$t.key" -out "$tmp/$t.crt" >/dev/null 2>&1 || die "openssl could not mint tenant-$t's cert"
  done
  local node c64 k64
  for t in a b; do
    if [ "$t" = a ]; then node="$nodeA"; else node="$nodeB"; fi
    c64="$(base64 < "$tmp/$t.crt" | tr -d '\n')"; k64="$(base64 < "$tmp/$t.key" | tr -d '\n')"
    sql+="
INSERT INTO secrets (id,name,cert_pem,key_pem,kind)
VALUES ('tenant-$t-cert','tenant-$t-cert',convert_from(decode('$c64','base64'),'UTF8'),convert_from(decode('$k64','base64'),'UTF8'),'tls_certificate')
ON CONFLICT (name) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,key_pem=EXCLUDED.key_pem,updated_at=now();
INSERT INTO gateways (id,name,port,protocol,tls_secret,node_selector,deleted_at)
VALUES ('tenant-$t-https','tenant-$t-https',8443,'HTTPS','tenant-$t-cert',jsonb_build_object('kubernetes.io/hostname','$node'),NULL)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port,protocol=EXCLUDED.protocol,tls_secret=EXCLUDED.tls_secret,node_selector=EXCLUDED.node_selector,deleted_at=NULL,updated_at=now();
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('tenant-$t-tls','tenant-$t-tls','tenant-$t-https',ARRAY['tenant-$t.local']::text[],'/','tenant-$t',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;"
  done
  rm -rf "$tmp"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  printf 'BEGIN;%s\nCOMMIT;\n' "$sql" | k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -f - >/dev/null
  ok "tenant-a-https -> $nodeA, tenant-b-https -> $nodeB (each with its own cert)"

  # assert_scope <node> <own> <other> — the node's Envoy holds its own tenant's
  # secret and not the other's, waiting out the reconcile poll and delivery.
  assert_scope() {
    local s i=0
    while :; do
      s="$(node_secrets "$1")"
      if printf '%s\n' "$s" | grep -qx "$2"; then break; fi
      i=$((i + 1)); [ "$i" -lt 15 ] || die "$1 never received $2 (holds: $(echo $s))"
      sleep 2
    done
    echo "  $1 SDS secrets: $(echo $s)"
    ! printf '%s\n' "$s" | grep -qx "$3" || die "$1 holds $3 — another tenant's key reached it"
    ok "$1 holds $2 and not $3"
  }
  # assert_serves <ip> <host> <backend> / assert_refuses <ip> <host>
  assert_serves() {
    local out; out="$(tls_get "$1" "$2")"
    has "$out" "CN=$2" && has "$out" "$3" || { printf '%s\n' "$out" | tail -15; die "$1 did not serve $2 with its own cert"; }
    ok "$1 serves $2 with CN=$2 -> $3"
  }
  assert_refuses() {
    local out; out="$(tls_get "$1" "$2")"
    ! has "$out" "CN=$2" && ! has "$out" "TENANT-" || { printf '%s\n' "$out" | tail -15; die "$1 presented $2's cert or served its backend — it holds that tenant's key"; }
    ok "$1 cannot serve $2 (presents no $2 cert: it holds no such key)"
  }

  section "each node's live Envoy SDS"
  assert_scope "$nodeA" tenant-a-cert tenant-b-cert
  assert_scope "$nodeB" tenant-b-cert tenant-a-cert

  section "each node serves its own tenant over TLS with that tenant's cert, and cannot present the other's"
  assert_serves "$ipA" tenant-a.local TENANT-A-BACKEND
  assert_serves "$ipB" tenant-b.local TENANT-B-BACKEND
  assert_refuses "$ipA" tenant-b.local
  assert_refuses "$ipB" tenant-a.local

  section "a node that reconnects is caught up with its own scope (config unchanged)"
  # Restart the control plane: a new replica turns Ready (/readyz) only after its
  # first publish, before any edge node can reach it, so with config unchanged
  # every node it serves afterwards is served by the late-join catch-up. Then
  # restart $nodeB's edge-proxy: the fresh Envoy holds nothing, so whatever it
  # ends up holding came from that catch-up.
  k -n "$INFRA_NS" rollout restart deploy/edge-control-plane >/dev/null
  wait_rollout deploy/edge-control-plane "$INFRA_NS" 240s
  local old new i=0
  old="$(ep_pod_on "$nodeB")"
  k -n edge delete pod "$old" --wait=true >/dev/null
  while :; do
    new="$(ep_pod_on "$nodeB")"
    [ -n "$new" ] && [ "$new" != "$old" ] && k -n edge wait --for=condition=Ready "pod/$new" --timeout=10s >/dev/null 2>&1 && break
    i=$((i + 1)); [ "$i" -lt 30 ] || die "no new edge-proxy became Ready on $nodeB"
    sleep 3
  done
  log "edge-proxy on $nodeB restarted: $old -> $new"
  assert_scope "$nodeB" tenant-b-cert tenant-a-cert
  assert_serves "$ipB" tenant-b.local TENANT-B-BACKEND
  assert_refuses "$ipB" tenant-a.local
  assert_scope "$nodeA" tenant-a-cert tenant-b-cert
  assert_serves "$ipA" tenant-a.local TENANT-A-BACKEND
  ok "PHASE 16 — per-node SDS scoping proven on two nodes, through a reconnect"
}

# ---- Phase 17 — the charts' NetworkPolicies refuse a pod outside the flows ----
# reach <ns> <deploy> <host> <port> — "connected" when a TCP connection from that
# workload opens (whatever the protocol says after); otherwise "dropped (curl
# exit N)": 28 = timed out (dropped on the way to a pod), 7 = refused or, from
# a node, denied in its own OUTPUT chain (connect() fails at once with EPERM).
# Exit 35 (TLS handshake failed — a plain-HTTP port such as edge-osb:8080) only
# happens after TCP connected, and some curl builds leave time_connect at 0 then.
reach() {
  local out
  out="$(k -n "$1" exec "deploy/$2" -- sh -c \
    'curl -sk --connect-timeout 4 -m 6 -o /dev/null -w "%{time_connect}" "$0"; echo " $?"' "https://$3:$4/" 2>/dev/null || true)"
  reach_verdict "$out"
}
# reach_from_node <node> <ip> <port> — the same probe from a kind node, i.e. from
# the node network the hostNetwork gateway sends from.
reach_from_node() {
  local out
  out="$(docker exec "$1" sh -c \
    'curl -sk --connect-timeout 4 -m 6 -o /dev/null -w "%{time_connect}" "$0"; echo " $?"' "https://$2:$3/" 2>/dev/null || true)"
  reach_verdict "$out"
}
reach_verdict() {  # "<time_connect> <curl exit>"
  if [ -z "$1" ]; then echo "error (the probe did not run)"
  elif [ "${1##* }" = 35 ] || awk -v t="${1% *}" 'BEGIN { exit !(t + 0 > 0) }'; then echo connected
  else echo "dropped (curl exit ${1##* })"; fi
}
reach_is() { local want="$1"; shift; case "$(reach "$@")" in "$want"*) return 0 ;; *) return 1 ;; esac; }
reach_from_node_is() { local want="$1"; shift; case "$(reach_from_node "$@")" in "$want"*) return 0 ;; *) return 1 ;; esac; }

phase17_network_policy() {
  section "PHASE 17 — the charts' NetworkPolicies: a pod outside the allowed flows is refused (red-first)"
  k -n "$INFRA_NS" get networkpolicy
  wait_rollout deploy/attacker sec3-attacker 60s
  local atk_ip; atk_ip="$(k -n sec3-attacker get pod -l app=attacker -o jsonpath='{.items[0].status.podIP}')"
  log "attacker pod $atk_ip (namespace sec3-attacker — no chart allows it)"

  # Every chart port, two sources each: the attacker (refused) and a node, the
  # gateway's own source (allowed) — so a drop is the policy, not a dead pod.
  # Policies have been in place since Phase 7, so nothing is reprogramming here.
  section "every chart's port: attacker dropped, gateway (node network) allowed"
  local node="${CLUSTER_NAME}-worker2" t svc port ip eps r
  for t in auth-service:50051:gw edge-control-plane:18000:gw edge-issuer:8081:gw \
           edge-osb:8080:gw edge-ratelimit:8082:gw edge-secrets:8082:none; do
    svc="${t%%:*}"; port="$(printf '%s' "$t" | cut -d: -f2)"
    eps="$(k -n "$INFRA_NS" get endpoints "$svc" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
    if [ -z "$eps" ]; then warn "$svc has no ready endpoints — skipped (a refused connection would prove nothing)"; continue; fi
    if [ "${t##*:}" = gw ]; then
      ip="$(k -n "$INFRA_NS" get svc "$svc" -o jsonpath='{.spec.clusterIP}')"
      retry 10 2 reach_from_node_is connected "$node" "$ip" "$port" || true
      r="$(reach_from_node "$node" "$ip" "$port")"
      echo "  node $node -> $svc:$port  =>  $r"
      if [ "$r" != connected ]; then
        k -n "$INFRA_NS" get endpoints "$svc" -o wide; k -n "$INFRA_NS" get pods -o wide | grep -E "^${svc}" || true
        die "$svc:$port refused to the gateway's node network ($r) — the policy blocks an allowed flow"
      fi
    fi
    r="$(reach sec3-attacker attacker "$svc.${INFRA_NS}.svc.cluster.local" "$port")"
    echo "  attacker -> $svc:$port  =>  $r"
    case "$r" in dropped*) ;; *) die "$svc:$port NOT refused to a pod outside the allowed flows ($r)" ;; esac
  done

  # RED first, on one chart: its policy switched off, the attacker gets in;
  # switched back on, it is dropped again — the refusal is the chart's policy.
  local AS="auth-service.${INFRA_NS}.svc.cluster.local"
  section "RED — auth-service NetworkPolicy OFF: the attacker reaches ext_authz :50051"
  h upgrade auth-service "$REPO_ROOT/deploy/helm/auth-service" -n "$INFRA_NS" --reuse-values \
    --set networkPolicy.enabled=false --wait --timeout 120s >/dev/null
  k -n "$INFRA_NS" get networkpolicy auth-service >/dev/null 2>&1 && die "RED setup: auth-service NetworkPolicy still present"
  retry 15 2 reach_is connected sec3-attacker attacker "$AS" 50051 \
    || die "RED baseline broken: the attacker cannot reach auth-service:50051 even with no policy ($(reach sec3-attacker attacker "$AS" 50051))"
  ok "RED — no policy: attacker($atk_ip) -> auth-service:50051 connected"

  section "GREEN — auth-service NetworkPolicy back ON: the same connection is dropped"
  h upgrade auth-service "$REPO_ROOT/deploy/helm/auth-service" -n "$INFRA_NS" --reuse-values \
    --set networkPolicy.enabled=true --wait --timeout 120s >/dev/null
  retry 15 2 reach_is dropped sec3-attacker attacker "$AS" 50051 \
    || die "GREEN FAIL: auth-service:50051 still reachable from the attacker with the chart's policy on"
  ok "GREEN — chart policy on: attacker($atk_ip) -> auth-service:50051 $(reach sec3-attacker attacker "$AS" 50051)"
  ok "PHASE 17 — every chart refuses a pod outside its allowed flows; the gateway's flows stay open"
}

# ---- Phase 18 — a user created through SCIM signs in through OIDC -------------
ISSUER_HTTPS="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"
SSO_EMAIL="sso-user@corp.local"   # Dex's static user (manifests/dex.yaml)
SSO_PASS="password"

# scim <method> <path> [json] — the IdP's SCIM client, from the minter pod.
# Prints the body, then a last line HTTP=<code>.
scim() {
  if [ -n "${3:-}" ]; then
    k -n tenant-secure exec minter -- curl -sk --max-time 10 -X "$1" "$ISSUER_HTTPS/scim/v2$2" \
      -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' -d "$3" -w '\nHTTP=%{http_code}'
  else
    k -n tenant-secure exec minter -- curl -sk --max-time 10 -X "$1" "$ISSUER_HTTPS/scim/v2$2" \
      -H "Authorization: Bearer $SCIM_TOKEN" -w '\nHTTP=%{http_code}'
  fi
}

# sso_sign_in — a browser's OIDC sign-in, from the minter pod: /sso/login on the
# issuer -> Dex's login form; post Dex the user's password -> Dex redirects to
# the issuer's /sso/callback, which answers. Body, then HTTP=<code>.
sso_sign_in() {
  k -n tenant-secure exec minter -- sh -c '
    J=/tmp/sso-jar; rm -f "$J"
    form="$(curl -sk --max-time 10 -L -c "$J" -b "$J" -o /dev/null -w "%{url_effective}" "$1/sso/login")"
    curl -sk --max-time 10 -L -c "$J" -b "$J" -w "\nHTTP=%{http_code}" \
      --data-urlencode "login=$2" --data-urlencode "password=$3" "$form"
  ' sh "$ISSUER_HTTPS" "$SSO_EMAIL" "$SSO_PASS"
}

# sso_login_redirects — the issuer's /sso/login sends the browser to the IdP
# (302), i.e. the issuer has discovered Dex; until then it answers 503.
sso_login_redirects() {
  [ "$(k -n tenant-secure exec minter -- curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
    "$ISSUER_HTTPS/sso/login" 2>/dev/null || true)" = 302 ]
}

http_of() { printf '%s' "${1##*HTTP=}"; }
body_of() { printf '%s' "${1%HTTP=*}"; }

phase18_scim_oidc() {
  section "PHASE 18 — a user created through SCIM signs in through OIDC (Dex stands in for the customer's IdP)"
  if docker pull "$DEX_IMAGE" >/dev/null 2>&1; then kind load docker-image --name "$CLUSTER_NAME" "$DEX_IMAGE" >/dev/null 2>&1 || true; fi
  k apply -f "$LOCAL_DIR/manifests/dex.yaml"
  k -n "$INFRA_NS" wait --for=condition=Ready certificate/dex-cert --timeout=120s >/dev/null
  wait_rollout deploy/dex "$INFRA_NS" 180s
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=60s >/dev/null
  # Dex's rollout can finish a moment before its Service answers; the issuer
  # discovers it on first use and keeps answering 503 until then.
  retry 30 2 sso_login_redirects || die "the issuer's /sso/login never redirected to Dex: $(k -n tenant-secure exec minter -- \
    curl -sk --max-time 10 -w '\nHTTP=%{http_code}' "$ISSUER_HTTPS/sso/login" 2>&1 || true)"
  ok "the issuer's /sso/login redirects to Dex"

  section "reset — delete $SSO_EMAIL if an earlier run left it"
  local out filter id
  filter="$(jq -rn --arg f "userName eq \"$SSO_EMAIL\"" '$f|@uri')"
  out="$(scim GET "/Users?filter=$filter")"
  [ "$(http_of "$out")" = 200 ] || die "SCIM list refused: $out"
  for id in $(body_of "$out" | jq -r '.Resources[]?.id'); do
    [ "$(http_of "$(scim DELETE "/Users/$id")")" = 204 ] || die "could not delete leftover user $id"
    log "deleted leftover $id"
  done

  section "RED — before SCIM provisions $SSO_EMAIL, Dex signs them in and the issuer refuses"
  out="$(sso_sign_in)"
  echo "  sign-in -> HTTP $(http_of "$out")  $(body_of "$out" | tr -d '\n')"
  [ "$(http_of "$out")" = 403 ] || die "RED FAIL: an IdP user SCIM never created got HTTP $(http_of "$out")"
  has "$(body_of "$out")" "not provisioned" || die "RED FAIL: refused for the wrong reason: $out"
  ok "RED — the IdP vouched for $SSO_EMAIL, and the issuer refused: not provisioned"

  section "SCIM — the IdP creates $SSO_EMAIL (POST /scim/v2/Users)"
  out="$(scim POST /Users "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$SSO_EMAIL\",\"name\":{\"givenName\":\"SSO\",\"familyName\":\"User\"},\"externalId\":\"dex-08a8684b\",\"active\":true}")"
  [ "$(http_of "$out")" = 201 ] || die "SCIM create failed: $out"
  id="$(body_of "$out" | jq -r .id)"
  [ "$(body_of "$out" | jq -r '.active')" = true ] || die "SCIM create: user not active: $out"
  ok "SCIM created $SSO_EMAIL as user $id"

  section "GREEN — the same Dex sign-in now yields a gateway token, and the gateway serves the SCIM user"
  out="$(sso_sign_in)"
  [ "$(http_of "$out")" = 200 ] || die "GREEN FAIL: provisioned user's OIDC sign-in got HTTP $(http_of "$out"): $(body_of "$out")"
  local TOK c b low
  TOK="$(body_of "$out" | jq -r '.access_token // empty')"
  [ -n "$TOK" ] || die "GREEN FAIL: sign-in answered 200 without an access_token: $out"
  c="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
  b="$(gw_body secure.local -H "Authorization: Bearer $TOK")"
  low="$(printf '%s' "$b" | tr 'A-Z' 'a-z')"
  printf '%s\n' "$b" | grep -iE 'X-User-Id|X-User-Email' | sed 's/^/    /'
  [ "$c" = 200 ] || die "GREEN FAIL: the gateway refused the SSO token (HTTP $c)"
  has "$low" "x-user-email: $SSO_EMAIL" || die "GREEN FAIL: whoami did not see x-user-email $SSO_EMAIL"
  has "$low" "x-user-id: $id" || die "GREEN FAIL: whoami did not see x-user-id $id (the SCIM user)"
  ok "GREEN — signed in through OIDC; secure.local served to x-user-email=$SSO_EMAIL x-user-id=$id"

  section "SCIM deprovision — PATCH active=false, and the next Dex sign-in is refused"
  out="$(scim PATCH "/Users/$id" '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}')"
  [ "$(http_of "$out")" = 200 ] && [ "$(body_of "$out" | jq -r .active)" = false ] || die "SCIM deactivate failed: $out"
  out="$(sso_sign_in)"
  echo "  sign-in -> HTTP $(http_of "$out")  $(body_of "$out" | tr -d '\n')"
  [ "$(http_of "$out")" = 403 ] || die "deprovisioned user's sign-in got HTTP $(http_of "$out") (expected 403)"
  ok "deactivated by SCIM -> sign-in refused"

  [ "$(http_of "$(scim DELETE "/Users/$id")")" = 204 ] || die "SCIM delete failed"
  ok "PHASE 18 — SCIM-provisioned user signed in through OIDC and reached the gateway; unprovisioned and deprovisioned were refused"
}

# ---- Phase 19 — confidential compute: no verified attestation, no workload ----
# kind has no confidential hardware: a labelled worker stands in for a
# confidential node, RuntimeClass confidential-mock for its runtime, and a mock
# attester for its TEE (manifests/confidential.yaml). What is real is the chart's
# option and the gate: the auth-service chart, installed as extra releases with
# confidential.enabled, starts only on that node and only once its attest init
# container has verified a fresh report.
CC_NODE="${CLUSTER_NAME}-worker"
CC_MEASUREMENT="a3f1c07e5b2d9e48c6f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6"  # = MOCK_MEASUREMENT
CC_ATTESTER="http://mock-attester.edge-attest.svc.cluster.local:8006/aa/evidence"

# cc_install <release> <trusted-key> <evidence-url> [helm args...] — the
# auth-service chart with its confidential-node option on. No --wait: a refused
# pod never becomes Ready. It mounts the auth-service release's certificate, so
# it does not issue one of its own (certificate.create=false).
cc_install() {
  local rel="$1" key="$2" url="$3"; shift 3
  h upgrade --install "$rel" "$REPO_ROOT/deploy/helm/auth-service" -n "$INFRA_NS" \
    -f "$LOCAL_DIR/values/values-auth-service.yaml" \
    --set certificate.create=false \
    --set confidential.enabled=true --set confidential.runtimeClassName=confidential-mock \
    --set confidential.attestation.image.repository=edge-attest --set "confidential.attestation.image.tag=$IMAGE_TAG" \
    --set "confidential.attestation.evidenceURL=$url" --set "confidential.attestation.trustedKey=$key" \
    --set "confidential.attestation.measurements={$CC_MEASUREMENT}" --set confidential.attestation.timeout=10s \
    "$@" >/dev/null
}

cc_pods() { k -n "$INFRA_NS" get pod -l "app.kubernetes.io/instance=$1" -o json; }

# cc_gate_exit <release> — the attest init container's last exit code (empty
# until it has exited once).
cc_gate_exit() {
  cc_pods "$1" | jq -r '.items[0].status.initContainerStatuses[0] // {} | (.state.terminated // .lastState.terminated // {}) | .exitCode // empty'
}
cc_gate_exited() { [ -n "$(cc_gate_exit "$1")" ]; }

# cc_assert_refused <release> <reason> — the gate exited non-zero for <reason>,
# and auth-service itself never started.
cc_assert_refused() {
  local rel="$1" want="$2" p code msg
  retry 45 2 cc_gate_exited "$rel" || { cc_pods "$rel" | jq '.items[0].status'; die "$rel: the attest gate never ran to an exit"; }
  p="$(cc_pods "$rel" | jq '.items[0]')"
  code="$(printf '%s' "$p" | jq -r '.status.initContainerStatuses[0] | (.state.terminated // .lastState.terminated) | .exitCode')"
  msg="$(printf '%s' "$p" | jq -r '.status.initContainerStatuses[0] | (.state.terminated // .lastState.terminated) | .message // ""')"
  echo "  $rel: attest exit $code — $msg"
  [ "$code" != 0 ] || die "$rel: the gate passed a pod it should have refused"
  has "$msg" "attestation REFUSED: $want" || die "$rel: refused, but not for '$want'"
  [ "$(printf '%s' "$p" | jq -r '[.status.containerStatuses[]? | select(.started == true or .state.running != null or .lastState.terminated != null)] | length')" = 0 ] \
    || die "$rel: auth-service started without a verified attestation"
  [ "$(printf '%s' "$p" | jq -r '.status.conditions[]? | select(.type == "Ready") | .status')" != True ] \
    || die "$rel: pod Ready without a verified attestation"
  ok "$rel refused — auth-service never started ($want)"
}

phase19_confidential() {
  section "PHASE 19 — confidential compute: the workload starts only with a verified attestation (mock TEE)"
  k label node "$CC_NODE" talyvor.io/confidential=true --overwrite >/dev/null
  local keys stranger pub
  keys="$(docker run --rm "edge-attest:$IMAGE_TAG" keygen)"
  stranger="$(docker run --rm "edge-attest:$IMAGE_TAG" keygen | jq -r .public_key)"
  pub="$(printf '%s' "$keys" | jq -r .public_key)"
  sed "s|edge-attest:local|edge-attest:$IMAGE_TAG|" "$LOCAL_DIR/manifests/confidential.yaml" | k apply -f - >/dev/null
  apply_secret edge-attest generic mock-attester-key --from-literal=private_key="$(printf '%s' "$keys" | jq -r .private_key)" >/dev/null
  k -n edge-attest rollout restart deploy/mock-attester >/dev/null
  wait_rollout deploy/mock-attester edge-attest 120s
  ok "node $CC_NODE labelled confidential; mock attester up, signing with $pub"

  section "RED — no attestation report (no attester at the URL): refused"
  cc_install auth-cc-noreport "$pub" "http://no-attester.edge-attest.svc.cluster.local:8006/aa/evidence"
  cc_assert_refused auth-cc-noreport "no attestation report"

  section "RED — a report signed by a key the chart does not trust: refused"
  cc_install auth-cc-untrusted "$stranger" "$CC_ATTESTER"
  cc_assert_refused auth-cc-untrusted "report is not signed by the trusted attester key"

  section "GREEN — a valid report from the trusted attester: auth-service starts, on the confidential node only"
  cc_install auth-cc "$pub" "$CC_ATTESTER" --set replicaCount=2
  wait_rollout deploy/auth-cc-auth-service "$INFRA_NS" 180s
  local pods n pod
  pods="$(cc_pods auth-cc)"
  n="$(printf '%s' "$pods" | jq '.items | length')"
  [ "$n" = 2 ] || die "GREEN: expected 2 auth-cc pods, found $n"
  for pod in $(printf '%s' "$pods" | jq -r '.items[].metadata.name'); do
    local p; p="$(printf '%s' "$pods" | jq --arg n "$pod" '.items[] | select(.metadata.name == $n)')"
    echo "  $pod: node $(printf '%s' "$p" | jq -r .spec.nodeName), runtimeClass $(printf '%s' "$p" | jq -r .spec.runtimeClassName)"
    [ "$(printf '%s' "$p" | jq -r .spec.nodeName)" = "$CC_NODE" ] || die "GREEN: $pod scheduled off the confidential node"
    [ "$(printf '%s' "$p" | jq -r .spec.runtimeClassName)" = confidential-mock ] || die "GREEN: $pod not under the confidential RuntimeClass"
    [ "$(printf '%s' "$p" | jq -r '.status.initContainerStatuses[0].state.terminated.exitCode')" = 0 ] || die "GREEN: $pod's gate did not pass"
    [ "$(printf '%s' "$p" | jq -r '.status.conditions[] | select(.type == "Ready") | .status')" = True ] || die "GREEN: $pod not Ready"
    local gl; gl="$(k -n "$INFRA_NS" logs "$pod" -c attest)"
    has "$gl" "attestation verified" && has "$gl" "\"measurement\":\"$CC_MEASUREMENT\"" \
      || die "GREEN: $pod's gate log does not show the verified measurement: $gl"
  done
  ok "GREEN — 2 auth-service pods verified $CC_MEASUREMENT, Ready, on $CC_NODE under confidential-mock"

  local rel
  for rel in auth-cc auth-cc-noreport auth-cc-untrusted; do h uninstall "$rel" -n "$INFRA_NS" >/dev/null; done
  ok "PHASE 19 — refused with no report and with an untrusted one; started with a valid one (real SEV-SNP/TDX attestation needs confidential VMs)"
}

# ---- Phase 20 — one HTTPS port, a cert per host (SNI via tls_inspector) -------
SNI_PORT="${SNI_PORT:-9443}"

# sni_get <node-ip> <host> [host-header] — HTTPS to that node's shared SNI port
# with SNI <host> (and Host <host> unless overridden), from inside the kind
# network; curl -v output, then "curl-exit=N".
sni_get() {
  local out rc=0
  out="$(docker exec "${CLUSTER_NAME}-control-plane" curl -skv --max-time 6 \
    --resolve "$2:$SNI_PORT:$1" -H "Host: ${3:-$2}" "https://$2:$SNI_PORT/" 2>&1)" || rc=$?
  printf '%s\ncurl-exit=%s\n' "$out" "$rc"
}

phase20_sni_certs() {
  section "PHASE 20 — one HTTPS port (:$SNI_PORT) serves two hosts, each with its own per-route cert"
  local node ip tmp pgpod t c64 k64 sql="
INSERT INTO gateways (id,name,port,protocol,tls_secret,node_selector,deleted_at)
VALUES ('sni-shared-https','sni-shared-https',$SNI_PORT,'HTTPS',NULL,'{}'::jsonb,NULL)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port,protocol=EXCLUDED.protocol,tls_secret=NULL,node_selector=EXCLUDED.node_selector,deleted_at=NULL,updated_at=now();"
  node="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].spec.nodeName}')"
  ip="$(k get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  [ -n "$ip" ] || die "PHASE20: no edge-proxy node IP"

  section "seed a cert per host and ONE shared HTTPS gateway whose two routes each carry their own cert"
  # The gateway has no tls_secret of its own: the certs live on the routes, so the
  # listener renders one SNI filter chain per host on the single shared port.
  tmp="$(mktemp -d)"
  for t in a b; do
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=sni-$t.local" \
      -keyout "$tmp/$t.key" -out "$tmp/$t.crt" >/dev/null 2>&1 || die "openssl could not mint sni-$t's cert"
    c64="$(base64 < "$tmp/$t.crt" | tr -d '\n')"; k64="$(base64 < "$tmp/$t.key" | tr -d '\n')"
    sql+="
INSERT INTO secrets (id,name,cert_pem,key_pem,kind)
VALUES ('sni-$t-cert','sni-$t-cert',convert_from(decode('$c64','base64'),'UTF8'),convert_from(decode('$k64','base64'),'UTF8'),'tls_certificate')
ON CONFLICT (name) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,key_pem=EXCLUDED.key_pem,updated_at=now();
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,tls_secret_name,deleted_at)
VALUES ('sni-$t','sni-$t','sni-shared-https',ARRAY['sni-$t.local']::text[],'/','tenant-$t',30,'none','sni-$t-cert',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,tls_secret_name=EXCLUDED.tls_secret_name,updated_at=now(),deleted_at=NULL;"
  done
  rm -rf "$tmp"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  printf 'BEGIN;%s\nCOMMIT;\n' "$sql" | k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -f - >/dev/null
  ok "sni-shared-https :$SNI_PORT — routes sni-a.local (cert sni-a-cert -> tenant-a), sni-b.local (cert sni-b-cert -> tenant-b)"

  section "each host on the shared port gets its own cert and its own backend ($node, $ip:$SNI_PORT)"
  local i=0 outA outB
  while :; do
    outA="$(sni_get "$ip" sni-a.local)"; outB="$(sni_get "$ip" sni-b.local)"
    has "$outA" "TENANT-A-BACKEND" && has "$outB" "TENANT-B-BACKEND" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$outA" | tail -15; printf '%s\n' "$outB" | tail -15; die "PHASE20 FAIL: the shared port never served both hosts"; }
    sleep 2
  done
  local h own other out
  for h in a b; do
    if [ "$h" = a ]; then out="$outA"; own=TENANT-A-BACKEND; other=b; else out="$outB"; own=TENANT-B-BACKEND; other=a; fi
    echo "  sni-$h.local:$SNI_PORT -> $(printf '%s\n' "$out" | grep -m1 -i 'subject:' | sed 's/^[* ]*//')"
    has "$out" "CN=sni-$h.local" || { printf '%s\n' "$out" | tail -15; die "PHASE20 FAIL: sni-$h.local was not served its own cert"; }
    ! has "$out" "CN=sni-$other.local" || die "PHASE20 FAIL: sni-$h.local was served sni-$other.local's cert"
    has "$out" "$own" || die "PHASE20 FAIL: sni-$h.local did not reach $own"
  done
  ok "sni-a.local -> CN=sni-a.local + TENANT-A-BACKEND; sni-b.local -> CN=sni-b.local + TENANT-B-BACKEND, one port"

  section "the Host is bound to the SNI: handshake as sni-b.local, ask for Host sni-a.local -> not tenant-a"
  # No route matches, so Envoy answers itself: 404, or 401 from the global
  # ext_authz (on since Phase 12) — anything but a 200 from tenant-a's backend.
  local status
  out="$(sni_get "$ip" sni-b.local sni-a.local)"
  status="$(printf '%s\n' "$out" | grep -m1 '^< HTTP/' | tr -d '\r' || true)"
  echo "  SNI sni-b.local, Host sni-a.local -> ${status:-<no HTTP answer>}"
  has "$out" "curl-exit=0" && [ -n "$status" ] && ! has "$status" " 200" && ! has "$out" "TENANT-A-BACKEND" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE20 FAIL: a request on sni-b.local's chain reached sni-a.local's route (or got no HTTP answer)"; }
  ok "a Host from another SNI finds no route — one host's chain cannot reach another host's route"

  section "an SNI no route names fails the TLS handshake (no cert, no body)"
  out="$(sni_get "$ip" unknown.local)"
  echo "  unknown.local:$SNI_PORT -> $(printf '%s\n' "$out" | tail -1)"
  has "$out" "curl-exit=35" || { printf '%s\n' "$out" | tail -15; die "PHASE20 FAIL: an unknown SNI did not fail the handshake (want curl exit 35)"; }
  ! has "$out" "CN=" && ! has "$out" "TENANT-" || die "PHASE20 FAIL: an unknown SNI was presented a cert or a body"
  ok "PHASE 20 — two per-route certs served by SNI on one HTTPS port; an unknown SNI is refused at the handshake"
}

# ---- Phase 21 — an OSB HTTPS service: public host, DNS upstream (B28.200) ----
# Runs after Phase 15 (the 'e2e' tenant key and the osb-stub upstream). The
# service is published as shop.e2e.local (the route's Host and the SNI its cert
# is served for) while Envoy forwards to the stub by its Service DNS name — a
# hostname upstream, so the control plane renders a STRICT_DNS cluster.
OSB_HTTPS_SERVICE="e2e-shop"
OSB_PUBLIC_HOST="shop.e2e.local"
OSB_DNS_UPSTREAM="echo.osb-stub.svc.cluster.local"

# envoy_update_rejected <edge-proxy-pod> — the sum of every xDS update_rejected
# counter (CDS, EDS, LDS, RDS, SDS) on that Envoy: config pushes it refused.
# Echoes "?" when the admin stats could not be read, never a silent 0.
envoy_update_rejected() {
  local pod="$1" pf out
  kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$pod" 19003:9901 >/dev/null 2>&1 &
  pf=$!
  sleep 5
  out="$(curl -s --max-time 8 'http://127.0.0.1:19003/stats?filter=update_rejected$' 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
  has "$out" "cluster_manager.cds.update_rejected" || { echo "?"; return; }
  printf '%s\n' "$out" | awk -F': ' '{s += $2} END {print s + 0}'
}

# rejected_by_pod — "<pod>=<update_rejected>" for every edge-proxy, one line.
rejected_by_pod() {
  local pod line=""
  for pod in $(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[*].metadata.name}'); do
    line+="$pod=$(envoy_update_rejected "$pod") "
  done
  printf '%s' "$line"
}

phase21_osb_https_public_host() {
  local port node ip tmp pgpod c64 k64 r out before after
  port="$(k -n "$INFRA_NS" get deploy -l app.kubernetes.io/instance=edge-osb,component=worker \
    -o jsonpath='{.items[0].spec.template.spec.containers[0].env[?(@.name=="SHARED_HTTPS_PORT")].value}')"
  [ -n "$port" ] || die "PHASE21: the edge-osb worker has no SHARED_HTTPS_PORT"
  section "PHASE 21 — an OSB HTTPS service: public host $OSB_PUBLIC_HOST, DNS upstream $OSB_DNS_UPSTREAM, shared port :$port"
  node="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].spec.nodeName}')"
  ip="$(k get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  [ -n "$ip" ] || die "PHASE21: no edge-proxy node IP"
  k apply -f "$LOCAL_DIR/manifests/osb-stub.yaml" >/dev/null
  wait_rollout deploy/echo osb-stub 120s

  section "seed the public host's cert (OSB only ever references it by name)"
  tmp="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$OSB_PUBLIC_HOST" \
    -keyout "$tmp/k" -out "$tmp/c" >/dev/null 2>&1 || die "openssl could not mint $OSB_PUBLIC_HOST's cert"
  c64="$(base64 < "$tmp/c" | tr -d '\n')"; k64="$(base64 < "$tmp/k" | tr -d '\n')"
  rm -rf "$tmp"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -c "
INSERT INTO secrets (id,name,cert_pem,key_pem,kind)
VALUES ('e2e-shop-cert','e2e-shop-cert',convert_from(decode('$c64','base64'),'UTF8'),convert_from(decode('$k64','base64'),'UTF8'),'tls_certificate')
ON CONFLICT (name) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,key_pem=EXCLUDED.key_pem,updated_at=now();" >/dev/null
  ok "secret e2e-shop-cert (CN=$OSB_PUBLIC_HOST)"

  r="$(osb_call DELETE "/v1/services/$OSB_HTTPS_SERVICE")"
  if [ "${r%% *}" = 202 ]; then
    log "removing a leftover '$OSB_HTTPS_SERVICE' from a prior run"
    osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  fi

  section "RED — before provisioning, $OSB_PUBLIC_HOST:$port is not served"
  out="$(SNI_PORT="$port" sni_get "$ip" "$OSB_PUBLIC_HOST")"
  echo "  $OSB_PUBLIC_HOST:$port -> $(printf '%s\n' "$out" | tail -1)"
  ! has "$out" "OSB-PROVISIONED-BACKEND" && ! has "$out" "CN=$OSB_PUBLIC_HOST" \
    || die "PHASE21 FAIL: $OSB_PUBLIC_HOST was served before the broker provisioned it — the proof would be vacuous"
  ok "RED proven — no cert, no body"

  before="$(rejected_by_pod)"
  echo "  update_rejected before: $before"
  has "$before" "=?" && die "PHASE21: could not read update_rejected from every edge-proxy ($before)"

  section "POST /v1/services — HTTPS, public_host $OSB_PUBLIC_HOST, host $OSB_DNS_UPSTREAM"
  r="$(osb_call POST /v1/services \
    "{\"name\":\"$OSB_HTTPS_SERVICE\",\"team\":\"$OSB_TEAM\",\"host\":\"$OSB_DNS_UPSTREAM\",\"port\":5678,\"public_host\":\"$OSB_PUBLIC_HOST\",\"protocol\":\"HTTPS\",\"tls_secret_name\":\"e2e-shop-cert\",\"auth_policy\":\"none\"}")"
  echo "  POST /v1/services -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 202 ] || die "PHASE21 FAIL: provision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"

  section "GREEN — $OSB_PUBLIC_HOST:$port serves its own cert and the stub body"
  local i=0
  while :; do
    out="$(SNI_PORT="$port" sni_get "$ip" "$OSB_PUBLIC_HOST")"
    has "$out" "OSB-PROVISIONED-BACKEND" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$out" | tail -15; die "PHASE21 FAIL: $OSB_PUBLIC_HOST:$port never served the stub"; }
    sleep 2
  done
  echo "  $OSB_PUBLIC_HOST:$port -> $(printf '%s\n' "$out" | grep -m1 -i 'subject:' | sed 's/^[* ]*//')  body: OSB-PROVISIONED-BACKEND"
  has "$out" "CN=$OSB_PUBLIC_HOST" || { printf '%s\n' "$out" | tail -15; die "PHASE21 FAIL: $OSB_PUBLIC_HOST was not served its own cert"; }

  local ctype
  ctype="$(envoy_config_dump "$(ep_pod)" | jq -r --arg n "osb-${OSB_TEAM}-${OSB_HTTPS_SERVICE}" \
    '.configs[]? | .dynamic_active_clusters[]? | select(.cluster.name == $n) | .cluster.type' 2>/dev/null || true)"
  echo "  Envoy cluster osb-${OSB_TEAM}-${OSB_HTTPS_SERVICE}: type ${ctype:-<absent>}"
  [ "$ctype" = STRICT_DNS ] || die "PHASE21 FAIL: the DNS upstream is not a STRICT_DNS cluster (got '${ctype:-<absent>}')"

  after="$(rejected_by_pod)"
  echo "  update_rejected after:  $after"
  [ "$after" = "$before" ] || die "PHASE21 FAIL: an Envoy refused the config this service produced (before: $before, after: $after)"
  ok "GREEN — CN=$OSB_PUBLIC_HOST + OSB-PROVISIONED-BACKEND via a STRICT_DNS upstream; no Envoy refused an update"

  section "DELETE /v1/services/$OSB_HTTPS_SERVICE — deprovision"
  r="$(osb_call DELETE "/v1/services/$OSB_HTTPS_SERVICE")"
  [ "${r%% *}" = 202 ] || die "PHASE21 FAIL: deprovision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  i=0
  while :; do
    out="$(SNI_PORT="$port" sni_get "$ip" "$OSB_PUBLIC_HOST")"
    ! has "$out" "OSB-PROVISIONED-BACKEND" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || die "PHASE21 FAIL: $OSB_PUBLIC_HOST still served after deprovision"
    sleep 2
  done
  ok "PHASE 21 — an OSB HTTPS service with a public host and a DNS upstream served, then deprovisioned"
}

# ---- Phase 22 — a second :443 gateway is refused; :443 keeps serving --------
# drop_collide_gateway removes the injected second :443 gateway (idempotent).
drop_collide_gateway() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 \
    -c "DELETE FROM gateways WHERE name='collide-443';" >/dev/null
}

phase22_listener_collision() {
  section "PHASE 22 — a second :443 gateway is refused and :443 keeps serving (red-first)"
  drop_collide_gateway   # clean any prior injection (idempotent)

  section "RED baseline — tenant-a/b serve 200 on :443; the listener_collision series exists"
  local ca cb m0 before
  ca="$(gw_code tenant-a.local)"; cb="$(gw_code tenant-b.local)"
  { [ "$ca" = 200 ] && [ "$cb" = 200 ]; } || die "PHASE22 baseline broken: tenant-a/b not both 200 ($ca/$cb)"
  m0="$(cp_scrape)"; before="$(blocked_of "$m0" listener_collision)"
  [ -n "$before" ] || die "PHASE22 FAIL: xds_snapshots_blocked_total{reason=\"listener_collision\"} is absent (it must exist from t=0)"
  log "tenant-a=$ca tenant-b=$cb ; listener_collision = $before"

  # Unpinned, so every node would hold two listeners on 0.0.0.0:443 next to local-gw.
  section "add a second gateway on :443 (collide-443, unpinned) via the data path"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -c "
INSERT INTO gateways (id,name,port,protocol,node_selector)
VALUES ('collide-443','collide-443',443,'HTTP','{}'::jsonb)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port,node_selector=EXCLUDED.node_selector,updated_at=now();" >/dev/null
  sleep 10   # reconciler poll (~5s) + guard trip

  section "GREEN — refused: counter rose, Envoy has no collide-443 listener, :443 still 200"
  local m1 after dump ca2 cb2
  m1="$(cp_scrape)"; after="$(blocked_of "$m1" listener_collision)"
  log "listener_collision = $after"
  awk -v a="$before" -v b="${after:-0}" 'BEGIN{exit !(b>a)}' \
    || { drop_collide_gateway; die "PHASE22 FAIL: listener_collision did not rise ($before -> ${after:-<absent>}) — the second :443 gateway was not refused"; }
  k -n "$INFRA_NS" logs deploy/edge-control-plane --tail=60 2>/dev/null \
    | grep -a 'refusing to publish colliding listeners' | tail -1 | sed 's/^/    /'
  dump="$(envoy_config_dump "$(ep_pod)")"
  has "$dump" collide-443 && { drop_collide_gateway; die "PHASE22 FAIL: collide-443 reached Envoy — the colliding snapshot was published"; }
  ca2="$(gw_code tenant-a.local)"; cb2="$(gw_code tenant-b.local)"
  { [ "$ca2" = 200 ] && [ "$cb2" = 200 ]; } \
    || { drop_collide_gateway; die "PHASE22 FAIL: :443 broke while a second :443 gateway existed ($ca2/$cb2)"; }
  ok "GREEN — collide-443 refused ($before -> $after); absent from Envoy; tenant-a=$ca2 tenant-b=$cb2"

  section "cleanup — remove the second gateway; publishing resumes"
  drop_collide_gateway
  local i=0
  while [ "$i" -lt 15 ]; do [ "$(gw_code tenant-a.local)" = 200 ] && break; i=$((i + 1)); sleep 2; done
  ok "PHASE 22 — a second :443 gateway refused; the last-good :443 kept serving"
}

# ---- Phase 23 — forged identity headers and path traversal (B28.202) --------
# harden-public is an open (auth_policy none) /public route on secure.local, next
# to Phase 12's jwt route on /. Routes load ORDER BY name, so harden-public is
# matched first: un-normalised, /public/../admin would ride it past ext_authz.
drop_harden_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 \
    -c "DELETE FROM routes WHERE name='harden-public';" >/dev/null
}

# path_code <host> <path> [extra curl args...] — status for a raw path; curl
# would collapse ../ itself without --path-as-is.
path_code() { local host="$1" path="$2"; shift 2; curl -s --path-as-is -o /dev/null -w '%{http_code}' --max-time 6 -H "Host: $host" "$@" "http://127.0.0.1:443$path" 2>/dev/null || true; }

phase23_connection_manager() {
  section "PHASE 23 — a forged x-user-id never reaches a backend; a path traversal is refused without a token"
  drop_harden_route   # clean any prior injection (idempotent)
  [ "$(gw_code secure.local)" = 401 ] || die "PHASE23 baseline broken: secure.local / without a token is not 401 (ext_authz off?)"

  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -c "
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('harden-public','harden-public','local-gw',ARRAY['secure.local']::text[],'/public','secure-whoami',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;" >/dev/null
  retry 20 2 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -H 'Host: secure.local' http://127.0.0.1:443/public)\" = 200 ]" \
    || { drop_harden_route; die "PHASE23: secure.local/public (auth_policy none) never served 200"; }
  ok "secure.local/public (none) serves 200 without a token; secure.local/ (jwt) is 401"

  section "forged identity headers on the open route — none may reach whoami"
  local body low
  body="$(curl -s --max-time 6 -H 'Host: secure.local' -H 'x-user-id: forged-admin' -H 'X-User-Teams: forged-root' \
    -H 'x_user_id: forged-underscore' -H 'x-user-email: forged@evil.example' -H 'x-gateway-auth: forged-transit' \
    -H 'x-auth-iss: forged-issuer' -H 'X-Forwarded-For: 6.6.6.6' http://127.0.0.1:443/public 2>/dev/null || true)"
  printf '%s\n' "$body" | grep -iE '^(GET|X-User|X_User|X-Gateway|X-Auth|X-Forwarded-For|X-Envoy-External)' | sed 's/^/    /'
  has "$body" 'GET /public' || { drop_harden_route; die "PHASE23: whoami did not answer the forged-header request"; }
  low="$(printf '%s' "$body" | tr 'A-Z' 'a-z')"
  local forged
  for forged in forged-admin forged-root forged-underscore forged@evil.example forged-transit forged-issuer; do
    has "$low" "$forged" && { drop_harden_route; die "PHASE23 FAIL: the client-forged value '$forged' reached the backend"; }
  done
  ok "x-user-id, x-user-teams, x_user_id, x-user-email, x-gateway-auth and x-auth-iss were all stripped"

  # use_remote_address: Envoy appends the TCP peer, so the rightmost entry is real.
  local xff last
  xff="$(printf '%s\n' "$body" | tr -d '\r ' | awk -F: 'tolower($1)=="x-forwarded-for"{print $2}')"
  last="${xff##*,}"
  { [ "$xff" != "$last" ] && [ "$last" != 6.6.6.6 ]; } \
    || { drop_harden_route; die "PHASE23 FAIL: X-Forwarded-For '$xff' — Envoy did not append the real peer after the forged 6.6.6.6"; }
  ok "the real peer address was appended after the forged one (X-Forwarded-For: $xff)"

  section "path traversal from the open route to the jwt route, without a token"
  local p c
  for p in '/public/../admin' '/public/%2e%2e/admin' '/public/..%2Fadmin'; do
    c="$(path_code secure.local "$p")"
    echo "    $p -> HTTP $c"
    [ "$c" = 200 ] && { drop_harden_route; die "PHASE23 FAIL: $p was served without a token (routed as /public)"; }
  done
  for p in '/public/../admin' '/public/%2e%2e/admin'; do
    [ "$(path_code secure.local "$p")" = 401 ] || { drop_harden_route; die "PHASE23 FAIL: $p is not 401 — it was not routed to the jwt route as /admin"; }
  done
  [ "$(path_code secure.local '/public/..%2Fadmin' -L)" = 401 ] \
    || { drop_harden_route; die "PHASE23 FAIL: /public/..%2Fadmin did not land on the jwt route (401) after its redirect"; }
  ok "every traversal was routed as /admin and refused with 401 (the %2F form via a redirect)"

  drop_harden_route
  ok "PHASE 23 — forged identity headers stripped; a path traversal is refused without a token"
}

# ---- Phase 24 — access logs and tracing on every listener (B28.205) ----------
# manifests/otel-collector.yaml prints every span and log record it receives, at
# otel-collector.monitoring:4317 — the chart's telemetry.otel default address.
# helm_set_otel <true|false> — the same LIVE --set flip as helm_set_extauthz,
# keeping ext_authz on (Phase 12's jwt route would refuse the snapshot without it).
helm_set_otel() {
  section "helm: telemetry.otel enabled=$1 (LIVE --set flip; ext_authz stays on)"
  h upgrade edge-control-plane "$REPO_ROOT/deploy/helm/edge-control-plane" -n "$INFRA_NS" \
    -f "$LOCAL_DIR/values/values-control-plane.yaml" \
    --set extAuthz.enabled=true --set telemetry.otel.enabled="$1" --wait --timeout 200s >/dev/null
  k -n edge rollout restart ds/edge-proxy >/dev/null
  k -n edge rollout status ds/edge-proxy --timeout=120s
}

# request_id <host> — the x-request-id header curl receives through :443.
request_id() {
  curl -s -D - -o /dev/null --max-time 6 -H "Host: $1" http://127.0.0.1:443/ 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="x-request-id"{print $2}'
}
collector_log() { k -n monitoring logs deploy/otel-collector --tail=-1 2>/dev/null || true; }
proxy_log() { k -n edge logs -l app.kubernetes.io/name=edge-proxy --tail=5000 --max-log-requests=10 2>/dev/null || true; }

# hcm_telemetry <edge-proxy-pod> — one line per connection manager on that Envoy:
# "<listener> <access loggers> <tracer>".
hcm_telemetry() {
  envoy_config_dump "$1" | jq -r '.configs[]? | .dynamic_listeners[]? | .active_state.listener as $l
    | $l.filter_chains[]?.filters[]? | select(.name == "envoy.filters.network.http_connection_manager")
    | "\($l.name) \([.typed_config.access_log[]?.name] | join(",")) \(.typed_config.tracing.provider.name // "no-tracer")"' 2>/dev/null
}

phase24_telemetry() {
  section "PHASE 24 — every listener logs its requests; the OTel collector shows the x-request-id curl received"
  k apply -f "$LOCAL_DIR/manifests/otel-collector.yaml" >/dev/null
  wait_rollout deploy/otel-collector monitoring
  helm_set_otel false   # idempotent: no-op on a first run

  section "RED — telemetry.otel off: the stdout access log has the request, the collector never sees it"
  local rid0
  retry 15 2 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -H 'Host: tenant-a.local' http://127.0.0.1:443/)\" = 200 ]" \
    || die "PHASE24 baseline broken: tenant-a.local is not serving 200"
  rid0="$(request_id tenant-a.local)"
  [ -n "$rid0" ] || die "PHASE24 FAIL: the response carries no x-request-id"
  retry 10 2 sh -c "kubectl --context '$KUBE_CONTEXT' -n edge logs -l app.kubernetes.io/name=edge-proxy --tail=5000 --max-log-requests=10 2>/dev/null | grep -q '\"request_id\":\"$rid0\"'" \
    || die "PHASE24 FAIL: no edge-proxy stdout access log line for x-request-id $rid0"
  proxy_log | grep "\"request_id\":\"$rid0\"" | tail -1 | sed 's/^/    /'
  sleep 5
  has "$(collector_log)" "$rid0" && die "PHASE24 RED broken: the collector saw $rid0 while telemetry.otel was off"
  ok "x-request-id $rid0 is in the stdout access log and not in the collector"

  helm_set_otel true
  retry 30 2 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -H 'Host: tenant-a.local' http://127.0.0.1:443/)\" = 200 ]" \
    || die "PHASE24: tenant-a.local stopped serving 200 after telemetry.otel was switched on"

  section "every connection manager on every edge-proxy logs to stdout and the collector, and traces"
  local pod lines bad=0
  for pod in $(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[*].metadata.name}'); do
    lines="$(hcm_telemetry "$pod")"
    [ -n "$lines" ] || die "PHASE24 FAIL: $pod reports no listeners in its config_dump"
    printf '%s\n' "$lines" | sed "s/^/    $pod: /"
    printf '%s\n' "$lines" | awk '$2 != "envoy.access_loggers.stdout,envoy.access_loggers.open_telemetry" || $3 != "envoy.tracers.opentelemetry" {bad=1} END {exit bad}' || bad=1
  done
  [ "$bad" = 0 ] || die "PHASE24 FAIL: a listener lacks the stdout or OpenTelemetry access log, or the OpenTelemetry tracer"
  ok "every listener carries both access logs and the OpenTelemetry tracer"

  section "GREEN — the collector shows the x-request-id curl received, as an access record and a span"
  local rid log
  rid="$(request_id tenant-a.local)"
  [ -n "$rid" ] || die "PHASE24 FAIL: the response carries no x-request-id"
  log "curl received x-request-id: $rid"
  retry 15 2 sh -c "kubectl --context '$KUBE_CONTEXT' -n monitoring logs deploy/otel-collector --tail=-1 2>/dev/null | grep -q 'guid:x-request-id: Str($rid)'" \
    || die "PHASE24 FAIL: the collector has no span tagged guid:x-request-id $rid"
  log="$(collector_log)"
  has "$log" "request_id: Str($rid)" || die "PHASE24 FAIL: the collector has no access-log record with request_id $rid"
  printf '%s\n' "$log" | grep -E "(request_id|guid:x-request-id): Str\($rid\)" | sed 's/^/    /'
  ok "PHASE 24 — the OTel collector shows x-request-id $rid as an access-log record and a trace span"
}

# ---- Phase 25 — fresh install: the default jwt auth gates an OSB service (B28.206)
# Runs right after phase 9, on the charts exactly as phase 7 installed them —
# nothing has switched ext_authz yet. A service provisioned WITHOUT naming an
# auth_policy gets the default, 'jwt'. While ext_authz was off by default, that
# one route made the control-plane refuse every snapshot (CFG-1), so the first
# normally-provisioned service froze the gateway. Now it is published and gated.
OSB_JWT_SERVICE="e2e-jwt"

phase25_default_jwt_osb() {
  section "PHASE 25 — fresh install: an OSB service with the default jwt auth → 401 without a token, 200 with one"
  local UMAIL="dev@edge.local" UPASS="devpassword-abc12345"
  local ISS="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"

  section "the control-plane runs ext_authz on, as installed (no --set, no overlay)"
  local ea
  ea="$(k -n "$INFRA_NS" get deploy edge-control-plane \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="EXT_AUTHZ_ENABLED")].value}')"
  [ "$ea" = true ] || die "PHASE25 FAIL: the installed control-plane has EXT_AUTHZ_ENABLED='$ea', want true (the chart default)"
  ok "EXT_AUTHZ_ENABLED=true on the installed control-plane"

  osb_register_tenant
  k apply -f "$LOCAL_DIR/manifests/osb-stub.yaml"
  wait_rollout deploy/echo osb-stub 120s
  local sip; sip="$(k -n osb-stub get svc echo -o jsonpath='{.spec.clusterIP}')"
  [ -n "$sip" ] || die "osb-stub echo ClusterIP unresolved"

  # Clean slate for re-runs: a prior run may have left the service provisioned.
  local r; r="$(osb_call DELETE "/v1/services/$OSB_JWT_SERVICE")"
  if [ "${r%% *}" = 202 ]; then
    log "removing a leftover '$OSB_JWT_SERVICE' from a prior run"
    osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  fi

  section "POST /v1/services — provision '$OSB_JWT_SERVICE' WITHOUT an auth_policy (the default is jwt)"
  r="$(osb_call POST /v1/services \
    "{\"name\":\"$OSB_JWT_SERVICE\",\"team\":\"$OSB_TEAM\",\"host\":\"$sip\",\"port\":5678,\"protocol\":\"HTTP\"}")"
  echo "  POST /v1/services -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 202 ] || die "PHASE25 FAIL: provision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  local ap
  ap="$(k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select auth_policy from routes where name='osb-${OSB_TEAM}-${OSB_JWT_SERVICE}' and deleted_at is null;" | tr -d '[:space:]')"
  [ "$ap" = jwt ] || die "PHASE25 FAIL: the provisioned route has auth_policy='$ap', want the default 'jwt'"
  ok "route osb-${OSB_TEAM}-${OSB_JWT_SERVICE} stored with auth_policy=jwt"

  section "no token → 401: the service is published AND gated"
  local i=0 c0=""
  while [ "$i" -lt 30 ]; do
    c0="$(gw80_code "$sip")"
    [ "$c0" = 401 ] && break
    i=$((i + 1)); sleep 2
  done
  echo "  :80 Host $sip, no Authorization -> HTTP $c0"
  [ "$c0" = 401 ] || die "PHASE25 FAIL: no-token request got $c0, want 401 (not published, or not gated)"
  local cg; cg="$(gw80_code "$sip" -H 'Authorization: Bearer not-a-jwt')"
  echo "  :80 Host $sip, garbage token    -> HTTP $cg"
  [ "$cg" = 401 ] || die "PHASE25 FAIL: garbage-token request got $cg, want 401"
  ok "401 without a valid token"

  section "a JWT from the issuer → 200 from the provisioned backend"
  local img
  for img in "$ATTACKER_IMAGE" "$WHOAMI_IMAGE"; do   # the minter pod's image, and whoami beside it
    if docker pull "$img" >/dev/null 2>&1; then kind load docker-image --name "$CLUSTER_NAME" "$img" >/dev/null 2>&1 || true; fi
  done
  k apply -f "$LOCAL_DIR/manifests/secure-backend.yaml" >/dev/null   # the in-cluster minter pod
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=120s >/dev/null
  k -n "$INFRA_NS" exec deploy/edge-issuer -- /issuer adduser --email "$UMAIL" --password "$UPASS" --team eng >/dev/null 2>&1 \
    && log "created issuer user $UMAIL" || log "issuer user $UMAIL already exists (adduser idempotent)"
  local TOK="" mi=0
  while [ "$mi" -lt 10 ]; do
    TOK="$(k -n tenant-secure exec minter -- curl -sk --max-time 6 -X POST "$ISS/login" \
      -H 'Content-Type: application/json' -d "{\"email\":\"$UMAIL\",\"password\":\"$UPASS\"}" 2>/dev/null \
      | jq -r '.access_token // empty' 2>/dev/null || true)"
    [ -n "$TOK" ] && break
    mi=$((mi + 1)); sleep 2
  done
  [ -n "$TOK" ] || die "PHASE25 FAIL: could not mint a JWT via POST /login"
  local c1="" b1="" j=0
  while [ "$j" -lt 15 ]; do
    c1="$(gw80_code "$sip" -H "Authorization: Bearer $TOK")"
    [ "$c1" = 200 ] && break
    j=$((j + 1)); sleep 2
  done
  b1="$(gw80_body "$sip" -H "Authorization: Bearer $TOK")"
  echo "  :80 Host $sip, Bearer <minted JWT> -> HTTP $c1  body: $(printf '%s' "$b1" | tr -d '\n')"
  { [ "$c1" = 200 ] && has "$b1" OSB-PROVISIONED-BACKEND; } \
    || die "PHASE25 FAIL: a valid JWT did not reach the provisioned backend (HTTP $c1)"
  ok "200 OSB-PROVISIONED-BACKEND with a valid token"

  local ca; ca="$(gw_code tenant-a.local)"
  [ "$ca" = 200 ] || die "PHASE25 FAIL: tenant-a.local (auth_policy=none, no token) got $ca with the jwt service present — the gateway froze"
  ok "tenant-a.local (auth_policy=none) still 200 without a token — nothing froze"

  section "deprovision '$OSB_JWT_SERVICE' (phase 12 switches ext_authz off, which a jwt route would freeze)"
  r="$(osb_call DELETE "/v1/services/$OSB_JWT_SERVICE")"
  [ "${r%% *}" = 202 ] || die "PHASE25 FAIL: deprovision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  ok "Phase 25 verified — on a fresh install an OSB service with jwt auth answers 401 without a token and 200 with one"
}

# ---- Phase 26 — an unsigned first-party image is refused at admission (B28.210)
# k8s/policies/verify-image-signatures.yaml: every ghcr.io/talyvor/* image (and, built before the
# move on 12 Oct 2026, every ghcr.io/gaboracnicolai/* one, against its own signer)
# must carry a keyless cosign signature from this repo's images.yaml, on main or
# a release tag. Kyverno fetches the signature from ghcr and checks it against
# the public Rekor log. Both Deployments have 0 replicas: the check is admission,
# so nothing has to pull or run.
phase26_signed_images() {
  section "PHASE 26 — an unsigned first-party image is refused at admission (red-first)"
  k apply -f "$REPO_ROOT/k8s/policies/verify-image-signatures.yaml"
  k wait --for=condition=Ready clusterpolicy/verify-image-signatures --timeout=120s >/dev/null \
    || die "PHASE26 FAIL: clusterpolicy/verify-image-signatures never became Ready"
  k create namespace signed-images --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n signed-images delete deploy unsigned respelled signed --ignore-not-found >/dev/null

  section "RED — a Deployment of an unsigned image MUST be DENIED"
  log "image: $UNSIGNED_IMAGE"
  local out="" denied="" i=0
  while [ "$i" -lt 20 ]; do
    out="$(k -n signed-images create deployment unsigned --image="$UNSIGNED_IMAGE" --replicas=0 2>&1 || true)"
    if has "$out" verify-image-signatures; then denied="$out"; break; fi
    k -n signed-images delete deploy unsigned --ignore-not-found >/dev/null 2>&1 || true
    i=$((i + 1)); sleep 3
  done
  [ -n "$denied" ] || die "PHASE26 FAIL: the unsigned image was ADMITTED: $out"
  echo "  Kyverno denial:"; printf '%s\n' "$denied" | fold -s -w 96 | sed 's/^/    /'
  # Denied for the missing signature, not because ghcr or Rekor was unreachable.
  has "$denied" "no signatures found" \
    || die "PHASE26 FAIL: denied, but not for a missing signature — see the denial above"
  ok "RED proven — Kyverno DENIED the unsigned image: no signatures found"

  section "RED — the same image with the registry spelled ghcr.io:443 MUST be DENIED too"
  out="$(k -n signed-images create deployment respelled --image="${UNSIGNED_IMAGE/ghcr.io/ghcr.io:443}" --replicas=0 2>&1 || true)"
  echo "  Kyverno denial:"; printf '%s\n' "$out" | fold -s -w 96 | sed 's/^/    /'
  has "$out" first-party-images-spelled-canonically \
    || die "PHASE26 FAIL: a ghcr.io:443 spelling was not refused — it would skip the signature check"
  ok "RED proven — a respelled registry does not skip the check"

  section "GREEN — a Deployment of a signed main build is admitted, pinned to the digest Kyverno verified"
  log "image: $SIGNED_IMAGE"
  local img
  img="$(k -n signed-images create deployment signed --image="$SIGNED_IMAGE" --replicas=0 \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>&1)" \
    || die "PHASE26 FAIL: the signed image was refused: $img"
  echo "  admitted as: $img"
  has "$img" "@sha256:" || die "PHASE26 FAIL: admitted without a digest — Kyverno did not verify it"
  ok "GREEN — the signed image was admitted and pinned to its digest"

  k delete namespace signed-images --wait=false >/dev/null
  ok "Phase 26 verified — an unsigned first-party image is refused at admission, a signed one runs pinned to its digest"
}

# ---- Phase 27 — agent certificates (SVIDs) from csi-driver-spiffe (B28.221) --
# csi-driver-spiffe gives every agent pod that mounts its volume a short-lived
# certificate for its SPIFFE ID, signed by the edge-spiffe CA (the edge-pki chart). That
# CA is the trust bundle: loaded through the edge-secrets custodian as a
# validation_context, named by an mtls route, and served to Envoy over SDS. A pod
# without a certificate from it never gets past the TLS handshake.
AGENT_PORT="${AGENT_PORT:-9446}"
AGENT_HOST="agents.edge.local"
SPIFFE_TRUST_DOMAIN="${SPIFFE_TRUST_DOMAIN:-edge.talyvor.local}"
AGENT_SPIFFE_ID="spiffe://$SPIFFE_TRUST_DOMAIN/ns/agents/sa/agent-alpha"

# custodian_put <name> <json body> — PUT /v1/secrets/<name> on edge-secrets, the
# only writer of the secrets table, as the operator from Phase 5's admin PKI.
# Echoes the HTTP status.
custodian_put() {
  local pki="$LOCAL_DIR/.pki-bootstrap" pf code
  kubectl --context "$KUBE_CONTEXT" -n "$INFRA_NS" port-forward svc/edge-secrets 18082:8082 >/dev/null 2>&1 &
  pf=$!
  sleep 4
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
    --cacert "$pki/admin-ca.crt" --cert "$pki/operator.crt" --key "$pki/operator.key" \
    -H 'Content-Type: application/json' --data-binary "$2" \
    "https://localhost:18082/v1/secrets/$1" 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
  printf '%s' "$code"
}

# agent_curl <pod> [curl args...] — from inside an agent pod, an HTTPS request to
# the mtls route on an edge-proxy node, trusting the route's server cert. Echoes
# curl's verbose output and "curl-exit=<rc>". Host is sent without the port, as
# Phase 20 does: the route's domain is the bare host.
agent_curl() {
  local pod="$1" out rc=0; shift
  out="$(k -n agents exec "$pod" -- curl -sv --max-time 8 --cacert /etc/agents-server-ca/ca.crt \
    --resolve "$AGENT_HOST:$AGENT_PORT:$AGENT_GW_IP" -H "Host: $AGENT_HOST" "$@" \
    "https://$AGENT_HOST:$AGENT_PORT/" 2>&1)" || rc=$?
  printf '%s\ncurl-exit=%s\n' "$out" "$rc"
}

# agent_tls_refusal <edge-proxy-pod> <counter> — that Envoy's count of handshakes
# the :AGENT_PORT listener refused for <counter>: fail_verify_no_cert (no client
# cert) or fail_verify_error (a cert the trust bundle did not sign). Echoes "?"
# when the admin stats could not be read, never a silent 0.
agent_tls_refusal() {
  local pf out
  kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$1" 19004:9901 >/dev/null 2>&1 &
  pf=$!
  sleep 4
  out="$(curl -s --max-time 8 -G --data-urlencode "filter=_${AGENT_PORT}\\.ssl\\.$2\$" \
    http://127.0.0.1:19004/stats 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
  has "$out" ".ssl.$2: " || { echo "?"; return; }
  printf '%s\n' "$out" | awk -F': ' '{s += $2} END {print s + 0}'
}

# assert_refused_at_handshake <pod> <counter> <why> [curl args...] — the pod gets
# no HTTP answer, and Envoy's <counter> rose: it refused the TLS handshake.
assert_refused_at_handshake() {
  local pod="$1" counter="$2" why="$3" before after out; shift 3
  before="$(agent_tls_refusal "$AGENT_GW_POD" "$counter")"
  out="$(agent_curl "$pod" "$@")"
  after="$(agent_tls_refusal "$AGENT_GW_POD" "$counter")"
  echo "  $pod -> $(printf '%s\n' "$out" | grep -m1 -iE 'alert|failure|reset' | sed 's/^[* ]*//') ($(printf '%s\n' "$out" | tail -1)); Envoy ssl.$counter $before -> $after"
  ! has "$out" "curl-exit=0" && ! has "$out" "< HTTP/" && ! has "$out" "TENANT-A-BACKEND" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE27 FAIL: $pod ($why) got an HTTP answer"; }
  [ "$before" != "?" ] && [ "$after" != "?" ] && [ "$after" -gt "$before" ] \
    || die "PHASE27 FAIL: $pod ($why) — Envoy's ssl.$counter did not rise ($before -> $after), so the handshake was not what refused it"
}

phase27_agent_svids() {
  section "PHASE 27 — agent certificates (SVIDs): only a pod holding one gets past the TLS handshake"
  local tmp node pgpod code body svid
  tmp="$(mktemp -d)"

  section "the agent trust root (edge-spiffe CA) and csi-driver-spiffe $CSI_DRIVER_SPIFFE_VERSION, trust domain $SPIFFE_TRUST_DOMAIN"
  # The edge-pki chart (Phase 4) installed the agent CA; nothing to apply.
  k -n cert-manager wait --for=condition=Ready certificate/edge-spiffe-ca --timeout=120s >/dev/null
  k wait --for=condition=Ready clusterissuer/edge-spiffe --timeout=120s >/dev/null
  h upgrade --install cert-manager-csi-driver-spiffe cert-manager-csi-driver-spiffe \
    --repo https://charts.jetstack.io --version "$CSI_DRIVER_SPIFFE_VERSION" -n cert-manager \
    -f "$REPO_ROOT/k8s/spiffe/csi-driver-spiffe-values.yaml" \
    --set app.trustDomain="$SPIFFE_TRUST_DOMAIN" --wait --timeout 5m >/dev/null
  ok "edge-spiffe ClusterIssuer Ready; csi-driver-spiffe running on every node"

  section "the trust bundle and the route's server cert, written through the edge-secrets custodian"
  k -n cert-manager get secret edge-spiffe-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > "$tmp/bundle.crt"
  grep -q 'BEGIN CERTIFICATE' "$tmp/bundle.crt" || die "PHASE27: the edge-spiffe CA has no ca.crt"
  body="$(jq -n --rawfile c "$tmp/bundle.crt" '{kind: "validation_context", cert_pem: $c}')"
  code="$(custodian_put agent-trust-bundle "$body")"
  [ "$code" = 200 ] || die "PHASE27: the custodian did not accept the trust bundle (HTTP $code)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$AGENT_HOST" \
    -addext "subjectAltName=DNS:$AGENT_HOST" -keyout "$tmp/server.key" -out "$tmp/server.crt" >/dev/null 2>&1 \
    || die "openssl could not mint the route's server cert"
  body="$(jq -n --rawfile c "$tmp/server.crt" --rawfile k "$tmp/server.key" '{kind: "tls_certificate", cert_pem: $c, key_pem: $k}')"
  code="$(custodian_put agents-server-cert "$body")"
  [ "$code" = 200 ] || die "PHASE27: the custodian did not accept the route's server cert (HTTP $code)"
  ok "agent-trust-bundle (validation_context) and agents-server-cert (tls_certificate) in the secrets table"

  section "an mtls route: $AGENT_HOST on :$AGENT_PORT, client certs checked against agent-trust-bundle"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
BEGIN;
INSERT INTO gateways (id,name,port,protocol,tls_secret,node_selector,deleted_at)
VALUES ('agents-https','agents-https',$AGENT_PORT,'HTTPS',NULL,'{}'::jsonb,NULL)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port,protocol=EXCLUDED.protocol,tls_secret=NULL,node_selector=EXCLUDED.node_selector,deleted_at=NULL,updated_at=now();
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,tls_secret_name,client_ca_secret_name,deleted_at)
VALUES ('agents','agents','agents-https',ARRAY['$AGENT_HOST']::text[],'/','tenant-a',30,'mtls','agents-server-cert','agent-trust-bundle',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,cluster_name=EXCLUDED.cluster_name,
  auth_policy=EXCLUDED.auth_policy,tls_secret_name=EXCLUDED.tls_secret_name,client_ca_secret_name=EXCLUDED.client_ca_secret_name,updated_at=now(),deleted_at=NULL;
COMMIT;
SQL
  ok "route agents (auth_policy=mtls) -> tenant-a"

  section "three agent pods: one with its SVID, one with no certificate, one with a certificate from another CA"
  k create namespace agents --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n agents create configmap agents-server-ca --from-file=ca.crt="$tmp/server.crt" --dry-run=client -o yaml | k apply -f - >/dev/null
  # Impersonates agent-alpha's SPIFFE ID, but is signed by a CA of its own.
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=agent-alpha" \
    -addext "subjectAltName=URI:$AGENT_SPIFFE_ID" -keyout "$tmp/foreign.key" -out "$tmp/foreign.crt" >/dev/null 2>&1 \
    || die "openssl could not mint the foreign cert"
  apply_secret agents generic foreign-cert --from-file=tls.crt="$tmp/foreign.crt" --from-file=tls.key="$tmp/foreign.key" >/dev/null
  sed "s|__IMAGE__|$ATTACKER_IMAGE|" "$LOCAL_DIR/manifests/agents.yaml" | k apply -f - >/dev/null
  k -n agents wait --for=condition=Ready pod --all --timeout=180s >/dev/null \
    || { k -n agents describe pod agent-alpha | tail -20; die "PHASE27: the agent pods did not become Ready"; }

  svid="$(k -n agents exec agent-alpha -- cat /var/run/secrets/spiffe.io/tls.crt)"
  printf '%s\n' "$svid" > "$tmp/svid.crt"
  echo "  agent-alpha's SVID: $(openssl x509 -in "$tmp/svid.crt" -noout -ext subjectAltName 2>/dev/null | tail -1 | sed 's/^ *//'), $(openssl x509 -in "$tmp/svid.crt" -noout -enddate)"
  has "$(openssl x509 -in "$tmp/svid.crt" -noout -ext subjectAltName 2>/dev/null)" "URI:$AGENT_SPIFFE_ID" \
    || die "PHASE27 FAIL: agent-alpha's certificate does not name $AGENT_SPIFFE_ID"
  openssl verify -CAfile "$tmp/bundle.crt" "$tmp/svid.crt" >/dev/null \
    || die "PHASE27 FAIL: agent-alpha's certificate does not chain to the trust bundle"
  ok "agent-alpha holds an SVID for $AGENT_SPIFFE_ID, signed by the edge-spiffe CA"

  AGENT_GW_POD="$(ep_pod)"
  node="$(k -n edge get pod "$AGENT_GW_POD" -o jsonpath='{.spec.nodeName}')"
  AGENT_GW_IP="$(k get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  [ -n "$AGENT_GW_IP" ] || die "PHASE27: no edge-proxy node IP"

  section "GREEN — agent-alpha presents its SVID: served ($node, $AGENT_GW_IP:$AGENT_PORT)"
  local i=0 out
  while :; do
    out="$(agent_curl agent-alpha --cert /var/run/secrets/spiffe.io/tls.crt --key /var/run/secrets/spiffe.io/tls.key)"
    has "$out" "TENANT-A-BACKEND" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$out" | tail -15; die "PHASE27 FAIL: agent-alpha was never served with its SVID"; }
    sleep 2
  done
  ok "agent-alpha -> $(printf '%s\n' "$out" | grep -m1 '^< HTTP/' | tr -d '\r' | sed 's/^< //') TENANT-A-BACKEND"

  section "RED — a pod with no certificate: refused at the TLS handshake"
  assert_refused_at_handshake no-svid fail_verify_no_cert "no certificate"
  ok "no-svid refused at the handshake for its missing certificate — no HTTP answer"

  section "RED — a certificate for the same SPIFFE ID from another CA: refused at the TLS handshake"
  assert_refused_at_handshake foreign-cert fail_verify_error "foreign CA" \
    --cert /var/run/secrets/spiffe.io/tls.crt --key /var/run/secrets/spiffe.io/tls.key
  ok "foreign-cert refused at the handshake — its certificate failed the trust bundle, no HTTP answer"

  rm -rf "$tmp"
  ok "PHASE 27 — csi-driver-spiffe issues agent SVIDs; with the trust bundle over SDS, a pod without one is refused at the TLS handshake"
}

# ---- Phase 28 — an egress gateway for agents (B28.222) ----------------------
# edge-egress is an Envoy Deployment agents use as their proxy. It connects to
# the control plane as node edge-egress/<pod> and receives only the egress
# snapshot: one listener that reaches the hosts in egress_destinations — plain
# HTTP sent on over TLS it verifies, CONNECT tunnelled with the agent's own TLS —
# and answers 403 for every other host. The mock provider's NetworkPolicy admits
# edge-egress alone, so an agent reaches it only through the gateway.
EGRESS_PROXY="http://edge-egress.edge.svc.cluster.local:3128"
MOCK_HOST="llm.mock-provider.svc.cluster.local"
IMPOSTOR_HOST="impostor.mock-provider.svc.cluster.local"

# agent_egress_curl [curl args...] — curl from the agent-egress pod. Echoes curl's
# verbose output and "curl-exit=<rc>".
agent_egress_curl() {
  local out rc=0
  out="$(k -n agents exec agent-egress -- curl -sv --max-time 8 "$@" 2>&1)" || rc=$?
  printf '%s\ncurl-exit=%s\n' "$out" "$rc"
}

# egress_stat <stat> — the edge-egress Envoy's counter <stat>, read from its
# localhost-only admin. Echoes "?" when it could not be read, never a silent 0.
egress_stat() {
  local pod pf out
  pod="$(k -n edge get pod -l app.kubernetes.io/name=edge-egress -o jsonpath='{.items[0].metadata.name}')"
  kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$pod" 19005:9901 >/dev/null 2>&1 &
  pf=$!
  sleep 4
  out="$(curl -s --max-time 8 -G --data-urlencode "filter=^$1\$" http://127.0.0.1:19005/stats 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
  has "$out" "$1: " || { echo "?"; return; }
  printf '%s\n' "$out" | awk -F': ' '{print $2 + 0; exit}'
}

phase28_egress_gateway() {
  section "PHASE 28 — the egress gateway: an agent reaches a mock TLS provider only through edge-egress"
  local tmp pgpod code body out i before after
  tmp="$(mktemp -d)"

  section "a mock TLS provider at $MOCK_HOST, its certificate from a CA of its own"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mock-provider-ca" \
    -keyout "$tmp/ca.key" -out "$tmp/ca.crt" >/dev/null 2>&1 || die "openssl could not mint the provider CA"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$MOCK_HOST" -keyout "$tmp/llm.key" -out "$tmp/llm.csr" >/dev/null 2>&1 \
    || die "openssl could not mint the provider key"
  printf 'subjectAltName=DNS:%s\n' "$MOCK_HOST" > "$tmp/san.cnf"
  openssl x509 -req -in "$tmp/llm.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -days 2 \
    -extfile "$tmp/san.cnf" -out "$tmp/llm.crt" >/dev/null 2>&1 || die "openssl could not sign the provider cert"
  k create namespace mock-provider --dry-run=client -o yaml | k apply -f - >/dev/null
  k create namespace agents --dry-run=client -o yaml | k apply -f - >/dev/null
  apply_secret mock-provider tls llm-tls --cert="$tmp/llm.crt" --key="$tmp/llm.key" >/dev/null
  k -n agents create configmap mock-provider-ca --from-file=ca.crt="$tmp/ca.crt" --dry-run=client -o yaml | k apply -f - >/dev/null
  sed -e "s|__WHOAMI__|$WHOAMI_IMAGE|" -e "s|__CURL__|$ATTACKER_IMAGE|" "$LOCAL_DIR/manifests/egress-provider.yaml" | k apply -f - >/dev/null
  k -n mock-provider rollout status deploy/llm --timeout=180s >/dev/null || die "PHASE28: the mock provider did not start"
  k -n agents wait --for=condition=Ready pod/agent-egress --timeout=180s >/dev/null || die "PHASE28: agent-egress did not become Ready"
  ok "mock provider serving HTTPS as $MOCK_HOST; agent-egress trusts its CA"

  section "CONTROL — before the provider's NetworkPolicy, the agent's direct call is served"
  i=0
  while :; do
    out="$(agent_egress_curl --cacert /etc/mock-provider-ca/ca.crt "https://$MOCK_HOST/")"
    has "$out" "Name: mock-llm" && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || { printf '%s\n' "$out" | tail -15; die "PHASE28: the direct call never worked, so blocking it would prove nothing"; }
    sleep 2
  done
  ok "agent-egress -> $MOCK_HOST directly: served (the path the policy is about to close is real)"

  section "the provider admits edge-egress alone (NetworkPolicy); the direct call is now dropped"
  k apply -f "$LOCAL_DIR/manifests/egress-provider-policy.yaml" >/dev/null
  i=0
  while :; do
    out="$(agent_egress_curl --cacert /etc/mock-provider-ca/ca.crt "https://$MOCK_HOST/")"
    has "$out" "curl-exit=28" && ! has "$out" "< HTTP/" && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || { printf '%s\n' "$out" | tail -15; die "PHASE28 FAIL: the direct call was not dropped"; }
    sleep 2
  done
  ok "agent-egress -> $MOCK_HOST directly: no answer, timed out (curl-exit=28)"

  section "edge-egress: one Envoy, xDS node edge-egress/<pod>"
  helm_install edge-egress edge || diag_fail edge-egress edge

  section "the provider's CA through the custodian, and two egress_destinations rows"
  body="$(jq -n --rawfile c "$tmp/ca.crt" '{kind: "validation_context", cert_pem: $c}')"
  code="$(custodian_put mock-provider-ca "$body")"
  [ "$code" = 200 ] || die "PHASE28: the custodian did not accept the provider CA (HTTP $code)"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
INSERT INTO egress_destinations (id, name, host, port, ca_secret_name) VALUES
  ('mock-llm', 'mock-llm', '$MOCK_HOST', 443, 'mock-provider-ca'),
  ('impostor', 'impostor', '$IMPOSTOR_HOST', 443, 'mock-provider-ca')
ON CONFLICT (name) DO UPDATE SET host=EXCLUDED.host, port=EXCLUDED.port,
  ca_secret_name=EXCLUDED.ca_secret_name, keyless=false, updated_at=now();
SQL
  ok "egress_destinations: mock-llm ($MOCK_HOST) and impostor ($IMPOSTOR_HOST), both verified against mock-provider-ca"

  section "GREEN — the same call through edge-egress (CONNECT, the agent's TLS end to end)"
  i=0
  while :; do
    out="$(agent_egress_curl -x "$EGRESS_PROXY" --cacert /etc/mock-provider-ca/ca.crt "https://$MOCK_HOST/")"
    has "$out" "Name: mock-llm" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$out" | tail -15; die "PHASE28 FAIL: the agent never reached the provider through edge-egress"; }
    sleep 2
  done
  ok "agent-egress -> edge-egress -> $MOCK_HOST: $(printf '%s\n' "$out" | grep -m1 '^< HTTP/' | tr -d '\r' | sed 's/^< //'), Name: mock-llm"

  section "GREEN — plain HTTP through edge-egress: edge-egress originates the TLS and verifies the provider"
  out="$(agent_egress_curl -x "$EGRESS_PROXY" "http://$MOCK_HOST/")"
  has "$out" "< HTTP/1.1 200" && has "$out" "Name: mock-llm" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE28 FAIL: plain HTTP through edge-egress did not reach the provider"; }
  ok "agent-egress -> edge-egress (TLS to $MOCK_HOST) -> 200, Name: mock-llm"

  section "RED — a host not in egress_destinations: 403 from edge-egress, CONNECT too"
  out="$(agent_egress_curl -x "$EGRESS_PROXY" "http://example.com/")"
  has "$out" "< HTTP/1.1 403" && has "$out" "edge-egress: destination not allowed" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE28 FAIL: an unlisted host was not refused by edge-egress"; }
  out="$(agent_egress_curl -x "$EGRESS_PROXY" "https://example.com/")"
  has "$out" "CONNECT tunnel failed, response 403" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE28 FAIL: CONNECT to an unlisted host was not refused"; }
  ok "example.com through edge-egress: 403, and CONNECT example.com:443: 403"

  section "RED — a listed host whose certificate does not name it: edge-egress refuses the upstream TLS"
  before="$(egress_stat cluster.egress_impostor.ssl.fail_verify_san)"
  out="$(agent_egress_curl -x "$EGRESS_PROXY" "http://$IMPOSTOR_HOST/")"
  after="$(egress_stat cluster.egress_impostor.ssl.fail_verify_san)"
  echo "  $IMPOSTOR_HOST -> $(printf '%s\n' "$out" | grep -m1 '^< HTTP/' | tr -d '\r' | sed 's/^< //'); Envoy ssl.fail_verify_san $before -> $after"
  has "$out" "< HTTP/1.1 503" && ! has "$out" "Name: mock-llm" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE28 FAIL: edge-egress served a host its certificate does not name"; }
  [ "$before" != "?" ] && [ "$after" != "?" ] && [ "$after" -gt "$before" ] \
    || die "PHASE28 FAIL: ssl.fail_verify_san did not rise ($before -> $after), so the certificate check was not what refused it"
  ok "$IMPOSTOR_HOST: 503 — the provider's certificate does not name it, and edge-egress would not talk to it"

  rm -rf "$tmp"
  ok "PHASE 28 — an agent reaches the mock TLS provider only through edge-egress: direct dropped, CONNECT and plain HTTP through the gateway served, unlisted hosts 403, a misnamed certificate refused"
}

# ---- Phase 29 — agent egress lockdown (B28.223) ------------------------------
# k8s/policies/agent-egress-lockdown.yaml: Kyverno writes a NetworkPolicy into
# every namespace labelled talyvor.io/agents=true that lets its pods reach
# cluster DNS and edge-egress:3128, nothing else. In Phase 28 the mock provider
# protected itself; a real provider is on the internet and answers anyone, so
# this phase first opens the mock provider to every pod. The only thing left
# between the agent and the provider is then the lockdown.
LOCKED_NS="agents-locked"

# locked_curl [curl args...] — curl from the agent-locked pod. Echoes curl's
# verbose output and "curl-exit=<rc>".
locked_curl() {
  local out rc=0
  out="$(k -n "$LOCKED_NS" exec agent-locked -- curl -sv --max-time 8 "$@" 2>&1)" || rc=$?
  printf '%s\ncurl-exit=%s\n' "$out" "$rc"
}

# locked_direct_dropped — the agent's direct call to the provider, retried until
# it times out with no HTTP answer (Calico programs a new policy within seconds).
locked_direct_dropped() {
  local out i=0
  while :; do
    out="$(locked_curl --cacert /etc/mock-provider-ca/ca.crt "https://$MOCK_HOST/")"
    has "$out" "curl-exit=28" && ! has "$out" "< HTTP/" && return 0
    i=$((i + 1))
    [ "$i" -lt 15 ] || { printf '%s\n' "$out" | tail -15; return 1; }
    sleep 2
  done
}

phase29_egress_lockdown() {
  section "PHASE 29 — egress lockdown: in an agent namespace, edge-egress is the only way out"
  local out i ca uid

  section "the mock provider opened to every pod, as a provider on the internet is"
  k -n mock-provider delete networkpolicy default-deny-ingress allow-from-edge-egress --ignore-not-found >/dev/null
  ok "mock-provider has no NetworkPolicy left"

  section "the agent-egress-lockdown ClusterPolicy"
  k apply -f "$REPO_ROOT/k8s/policies/agent-egress-lockdown.yaml" >/dev/null
  k wait --for=condition=Ready clusterpolicy/agent-egress-lockdown --timeout=120s >/dev/null \
    || die "PHASE29: the agent-egress-lockdown policy did not become Ready"
  ok "clusterpolicy/agent-egress-lockdown Ready"

  section "an agent in $LOCKED_NS, a namespace not yet labelled as holding agents"
  # A re-run starts from an unlabelled namespace again.
  k delete namespace "$LOCKED_NS" --ignore-not-found --wait=true --timeout=180s >/dev/null
  ca="$(k -n agents get configmap mock-provider-ca -o jsonpath='{.data.ca\.crt}')"
  [ -n "$ca" ] || die "PHASE29: no mock-provider-ca configmap in agents — run phase28_egress_gateway first"
  k create namespace "$LOCKED_NS" >/dev/null
  k -n "$LOCKED_NS" create configmap mock-provider-ca --from-literal=ca.crt="$ca" >/dev/null
  sed "s|__CURL__|$ATTACKER_IMAGE|" "$LOCAL_DIR/manifests/agent-lockdown.yaml" | k apply -f - >/dev/null
  k -n "$LOCKED_NS" wait --for=condition=Ready pod/agent-locked --timeout=180s >/dev/null \
    || die "PHASE29: agent-locked did not become Ready"
  ok "agent-locked running in $LOCKED_NS"

  section "CONTROL — before the label, the agent's direct call to the provider is served"
  i=0
  while :; do
    out="$(locked_curl --cacert /etc/mock-provider-ca/ca.crt "https://$MOCK_HOST/")"
    has "$out" "Name: mock-llm" && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || { printf '%s\n' "$out" | tail -15; die "PHASE29: the direct call never worked, so blocking it would prove nothing"; }
    sleep 2
  done
  ok "agent-locked -> $MOCK_HOST directly: served (nothing else stands in the way)"

  section "$LOCKED_NS labelled talyvor.io/agents=true: Kyverno writes the lockdown"
  k label namespace "$LOCKED_NS" talyvor.io/agents=true --overwrite >/dev/null
  i=0
  until k -n "$LOCKED_NS" get networkpolicy agent-egress-lockdown >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || die "PHASE29 FAIL: Kyverno did not write agent-egress-lockdown into $LOCKED_NS"
    sleep 2
  done
  ok "networkpolicy $LOCKED_NS/agent-egress-lockdown: egress to kube-dns:53 and edge/edge-egress:3128 only"

  section "RED — the same direct call is now dropped"
  locked_direct_dropped || die "PHASE29 FAIL: with the lockdown in place the agent still reached the provider directly"
  ok "agent-locked -> $MOCK_HOST directly: no answer, timed out (curl-exit=28)"

  section "GREEN — the same call through edge-egress is served"
  out="$(locked_curl -x "$EGRESS_PROXY" --cacert /etc/mock-provider-ca/ca.crt "https://$MOCK_HOST/")"
  has "$out" "Name: mock-llm" \
    || { printf '%s\n' "$out" | tail -15; die "PHASE29 FAIL: the locked agent could not reach the provider through edge-egress"; }
  ok "agent-locked -> edge-egress -> $MOCK_HOST: $(printf '%s\n' "$out" | grep -m1 '^< HTTP/' | tr -d '\r' | sed 's/^< //'), Name: mock-llm"

  section "the lockdown stays: deleted from the namespace, Kyverno writes it back"
  uid="$(k -n "$LOCKED_NS" get networkpolicy agent-egress-lockdown -o jsonpath='{.metadata.uid}')"
  k -n "$LOCKED_NS" delete networkpolicy agent-egress-lockdown >/dev/null
  i=0
  while :; do
    out="$(k -n "$LOCKED_NS" get networkpolicy agent-egress-lockdown -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    [ -n "$out" ] && [ "$out" != "$uid" ] && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || die "PHASE29 FAIL: the deleted lockdown was not written back"
    sleep 2
  done
  locked_direct_dropped || die "PHASE29 FAIL: after the lockdown was written back the agent reached the provider directly"
  ok "agent-egress-lockdown written back (uid $uid -> $out); the direct call is dropped again"

  ok "PHASE 29 — in a namespace labelled talyvor.io/agents=true the agent's direct call is dropped, the same call through edge-egress is served, and the lockdown cannot be deleted away"
}

# ---- Phase 30 — keyless agents (B28.224) -------------------------------------
# A keyless egress destination takes no credential from the agent. edge-egress
# sends its plain-HTTP requests to the auth-service in agent mode: the agent
# proves who it is with its ServiceAccount token (projected for audience
# edge-egress) in Proxy-Authorization, every credential it sent is removed, and
# a signed transit assertion (x-gateway-auth) is added for Lens to accept.
# CONNECT to a keyless host is refused, and the agent sits in Phase 29's locked
# namespace, so the gateway's plain-HTTP path is the only way out for its key.
KEYLESS_AUD="edge-egress"

# keyless_curl <with-token|no-token> [curl args...] — curl from agent-keyless with
# the key planted in it ($OPENAI_API_KEY, read in the pod) as Authorization,
# x-api-key and api-key. with-token adds its workload token as
# Proxy-Authorization. Echoes curl's verbose output, then the response body,
# then "curl-exit=<rc>". The body is held until curl exits and everything leaves
# the pod on one stream: a body on a second stream once landed inside one of
# curl's verbose lines ("{ [983 bytes dName: mock-llm"), and provider_echo then
# dropped the provider's first line with curl's.
keyless_curl() {
  local out rc=0
  out="$(k -n "$LOCKED_NS" exec agent-keyless -- sh -c '
    exec 2>&1
    mode=$1; shift
    if [ "$mode" = with-token ]; then
      set -- --proxy-header "Proxy-Authorization: Bearer $(cat /var/run/secrets/talyvor/token)" "$@"
    fi
    body="$(curl -sv --max-time 8 -H "Authorization: Bearer $OPENAI_API_KEY" \
      -H "x-api-key: $OPENAI_API_KEY" -H "api-key: $OPENAI_API_KEY" "$@")"; rc=$?
    printf "%s\n" "$body"
    exit "$rc"' _ "$@" 2>&1)" || rc=$?
  printf '%s\ncurl-exit=%s\n' "$out" "$rc"
}

# provider_echo — what the provider received, from keyless_curl's output: the
# mock echoes the request it was sent; curl's own lines (> < * { }) are dropped.
provider_echo() {
  printf '%s\n' "$1" | tr -d '\r' | grep -v -e '^[<>*{}] ' -e '^[<>*]$' -e '^curl-exit='
}

phase30_keyless_agents() {
  section "PHASE 30 — keyless agents: a key planted in the agent never reaches the provider"
  local out echo i iss issuers pgpod planted sa_sub ga ah ap as claims jwks pf tdir

  section "auth-service trusts the cluster's ServiceAccount issuer for audience $KEYLESS_AUD"
  # The issuer's public keys are readable without a token, as any OIDC
  # provider's are.
  k create clusterrolebinding edge-sa-issuer-discovery --clusterrole=system:service-account-issuer-discovery \
    --group=system:unauthenticated --dry-run=client -o yaml | k apply -f - >/dev/null
  iss="$(k get --raw /.well-known/openid-configuration | jq -r .issuer)"
  [ -n "$iss" ] && [ "$iss" != null ] || die "PHASE30: the API server publishes no ServiceAccount issuer"
  issuers="$(jq -cn --arg iss "$iss" --arg aud "$KEYLESS_AUD" '[{issuer: $iss, audience: $aud,
    jwks_url: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
    ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}]')"
  k -n "$INFRA_NS" patch secret auth-service-secrets --type merge \
    -p "$(jq -cn --arg v "$issuers" '{stringData: {JWT_ISSUERS: $v}}')" >/dev/null
  k -n "$INFRA_NS" rollout restart deploy/auth-service >/dev/null
  k -n "$INFRA_NS" rollout status deploy/auth-service --timeout=180s >/dev/null \
    || { k -n "$INFRA_NS" logs deploy/auth-service --tail=30 || true; die "PHASE30: auth-service did not come back trusting $iss"; }
  ok "auth-service trusts $iss (audience $KEYLESS_AUD)"

  section "agent-keyless in $LOCKED_NS: a key planted in its environment, its ServiceAccount token projected"
  planted="sk-planted-$(openssl rand -hex 12)"
  sa_sub="system:serviceaccount:$LOCKED_NS:agent-keyless"
  k -n "$LOCKED_NS" get networkpolicy agent-egress-lockdown >/dev/null 2>&1 \
    || die "PHASE30: $LOCKED_NS is not locked down — run phase29_egress_lockdown first"
  k -n "$LOCKED_NS" delete pod agent-keyless --ignore-not-found --wait=true >/dev/null
  sed -e "s|__CURL__|$ATTACKER_IMAGE|" -e "s|__PLANTED__|$planted|" "$LOCAL_DIR/manifests/agent-keyless.yaml" \
    | k apply -f - >/dev/null
  k -n "$LOCKED_NS" wait --for=condition=Ready pod/agent-keyless --timeout=180s >/dev/null \
    || die "PHASE30: agent-keyless did not become Ready"
  ok "agent-keyless running as $sa_sub, OPENAI_API_KEY=${planted:0:14}…"

  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q >/dev/null \
    <<<"UPDATE egress_destinations SET keyless = false, updated_at = now() WHERE name = 'mock-llm';"

  section "CONTROL — while mock-llm is not keyless, the planted key reaches the provider through edge-egress"
  i=0
  while :; do
    out="$(keyless_curl no-token -x "$EGRESS_PROXY" "http://$MOCK_HOST/v1/models?key=$planted")"
    echo="$(provider_echo "$out")"
    has "$echo" "Name: mock-llm" && has "$echo" "Authorization: Bearer $planted" && has "$echo" "key=$planted" && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || { printf '%s\n' "$out" | tail -25; die "PHASE30: the provider's echo never showed the planted key, so its absence later would prove nothing"; }
    sleep 2
  done
  ok "mock-llm (not keyless) echoed Authorization: Bearer ${planted:0:14}… and key=${planted:0:14}… — the provider sees what the agent sends"

  section "mock-llm marked keyless"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q >/dev/null \
    <<<"UPDATE egress_destinations SET keyless = true, updated_at = now() WHERE name = 'mock-llm';"

  section "RED — the planted key alone, no workload token: 407 from edge-egress, the provider never reached"
  i=0
  while :; do
    out="$(keyless_curl no-token -x "$EGRESS_PROXY" "http://$MOCK_HOST/v1/models")"
    has "$out" "< HTTP/1.1 407" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$out" | tail -25; die "PHASE30 FAIL: mock-llm never became keyless on edge-egress"; }
    sleep 2
  done
  has "$out" "Proxy-Authorization: Bearer" && ! has "$(provider_echo "$out")" "Name: mock-llm" \
    || { printf '%s\n' "$out" | tail -25; die "PHASE30 FAIL: the 407 did not come from edge-egress"; }
  ok "keyless mock-llm without a workload token: $(printf '%s\n' "$out" | grep -m1 '^< HTTP/' | tr -d '\r' | sed 's/^< //') — $(provider_echo "$out" | head -1)"

  section "GREEN — with its workload token: served, and nothing the agent sent as a key reaches the provider"
  # key= and its percent-encoded twin %6Bey=, which a provider decodes to key.
  out="$(keyless_curl with-token -x "$EGRESS_PROXY" "http://$MOCK_HOST/v1/models?z=1&key=$planted&a=2&%6Bey=$planted")"
  echo="$(provider_echo "$out")"
  has "$out" "< HTTP/1.1 200" && has "$echo" "Name: mock-llm" \
    || { printf '%s\n' "$out" | tail -25; die "PHASE30 FAIL: the keyless agent was not served through edge-egress"; }
  echo "  the provider received:"
  printf '%s\n' "$echo" | grep -E '^(GET |Authorization|Proxy-Authorization|X-Api-Key|Api-Key|X-Gateway-Auth)' | cut -c1-90 | sed 's/^/    /'
  ! has "$echo" "$planted" \
    || die "PHASE30 FAIL: the key planted in the agent reached the provider"
  ! has "$echo" "Authorization:" && ! has "$echo" "X-Api-Key:" && ! has "$echo" "Api-Key:" \
    || die "PHASE30 FAIL: a credential header reached the provider (the workload token included)"
  has "$echo" "GET /v1/models?a=2&z=1 HTTP/1.1" \
    || die "PHASE30 FAIL: the provider did not receive the URL without its key="

  section "GREEN — the provider received the gateway's signed assertion for $sa_sub instead"
  ga="$(printf '%s\n' "$echo" | awk -F': ' 'tolower($1)=="x-gateway-auth"{print $2; exit}')"
  IFS=. read -r ah ap as <<<"$ga"
  [ -n "$as" ] || die "PHASE30 FAIL: no signed x-gateway-auth assertion reached the provider"
  claims="$(b64url_d "$ap")"
  printf '%s' "$claims" | jq -e --arg sub "$sa_sub" --arg iss "$iss" --arg htu "$MOCK_HOST/v1/models?a=2&z=1" \
    '.sub == $sub and .amr == "agent" and .idp == $iss and .htm == "GET" and .htu == $htu and (.exp - .iat) <= 60' >/dev/null \
    || die "PHASE30 FAIL: the assertion does not name this agent and this request: $claims"
  kubectl --context "$KUBE_CONTEXT" -n "$INFRA_NS" port-forward deploy/auth-service 19091:9090 >/dev/null 2>&1 &
  pf=$!; sleep 4
  jwks="$(curl -s --max-time 6 http://127.0.0.1:19091/.well-known/transit-jwks.json 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  [ "$(printf '%s' "$jwks" | jq -r '.keys[0].kid')" = "$(b64url_d "$ah" | jq -r .kid)" ] \
    || die "PHASE30 FAIL: /.well-known/transit-jwks.json does not publish the assertion's kid (got: ${jwks:-nothing})"
  tdir="$(mktemp -d)"
  { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; b64url_d "$(printf '%s' "$jwks" | jq -r '.keys[0].x')"; } > "$tdir/pub.der"
  openssl pkey -pubin -inform DER -in "$tdir/pub.der" -out "$tdir/pub.pem" 2>/dev/null
  printf '%s' "$ah.$ap" > "$tdir/msg"; b64url_d "$as" > "$tdir/sig"
  openssl pkeyutl -verify -pubin -inkey "$tdir/pub.pem" -rawin -in "$tdir/msg" -sigfile "$tdir/sig" >/dev/null 2>&1 \
    || die "PHASE30 FAIL: the assertion does not verify against the published transit key"
  rm -rf "$tdir"
  echo "  x-gateway-auth claims: $(printf '%s' "$claims" | jq -c '{sub,amr,idp,htm,htu,ttl:(.exp-.iat)}')"
  ok "200; the provider got no Authorization, X-Api-Key, Api-Key or key=, and an EdDSA assertion for $sa_sub that verifies with the published key"

  section "RED — CONNECT to the keyless host: 403, a tunnel would carry the key past the gateway"
  out="$(keyless_curl with-token -x "$EGRESS_PROXY" "https://$MOCK_HOST/v1/models")"
  has "$out" "CONNECT tunnel failed, response 403" \
    || { printf '%s\n' "$out" | tail -25; die "PHASE30 FAIL: CONNECT to a keyless host was not refused"; }
  ok "CONNECT $MOCK_HOST:443 from agent-keyless: 403"

  section "RED — the direct path: dropped by $LOCKED_NS's lockdown"
  i=0
  while :; do
    out="$(keyless_curl no-token -k "https://$MOCK_HOST/v1/models")"
    has "$out" "curl-exit=28" && ! has "$out" "< HTTP/" && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || { printf '%s\n' "$out" | tail -25; die "PHASE30 FAIL: agent-keyless reached the provider directly"; }
    sleep 2
  done
  ok "agent-keyless -> $MOCK_HOST directly: no answer, timed out (curl-exit=28)"

  ok "PHASE 30 — keyless agents: the key planted in agent-keyless never reached the provider (stripped through edge-egress, CONNECT 403, direct dropped), and the provider got the gateway's signed assertion for $sa_sub instead"
}

# ---- Phase 31 — per-agent rate limits and the decision log (B28.228) ---------
# edge-egress counts every request against two buckets of the agent's own: the
# ServiceAccount the auth-service verified (it hands it to Envoy as ext_authz
# metadata), and the pod address the request came from. When either is empty
# the agent gets 429. Every decision edge-egress makes — sent on, refused,
# refused for the limit — is logged with the agent in it and appended to the
# control plane's decision log, a hash chain the admin API exports as NDJSON and
# scripts/verify-decisions.sh checks. mock-llm is keyless (Phase 30), so the
# agents below prove who they are with their ServiceAccount tokens.
RL_PER_MINUTE=5
CP_ADMIN_KEY="local-dev-cp-admin-key"

# rl_burst <pod> <n> — <n> requests from <pod> in $LOCKED_NS through edge-egress
# to mock-llm with the pod's workload token, back to back in one exec. Echoes
# the status codes, space-separated.
rl_burst() {
  k -n "$LOCKED_NS" exec "$1" -- sh -c '
    for i in $(seq 1 "$1"); do
      curl -s -o /dev/null -w "%{http_code} " --max-time 8 -x "$2" \
        --proxy-header "Proxy-Authorization: Bearer $(cat /var/run/secrets/talyvor/token)" "http://$3/v1/models"
    done' _ "$2" "$EGRESS_PROXY" "$MOCK_HOST" 2>/dev/null || true
}

# rl_headers <pod> — one more request from <pod>; echoes its status line and
# its Retry-After and X-RateLimit-* headers.
rl_headers() {
  k -n "$LOCKED_NS" exec "$1" -- sh -c '
    curl -s -D - -o /dev/null --max-time 8 -x "$1" \
      --proxy-header "Proxy-Authorization: Bearer $(cat /var/run/secrets/talyvor/token)" "http://$2/v1/models"' \
    _ "$EGRESS_PROXY" "$MOCK_HOST" 2>/dev/null | tr -d '\r' | grep -iE '^(HTTP/|retry-after|x-ratelimit-)' || true
}

# egress_stats <regex> — the edge-egress Envoy's stats matching <regex>, one
# "name: value" per line (nothing when it could not read them).
egress_stats() {
  local pod pf
  pod="$(k -n edge get pod -l app.kubernetes.io/name=edge-egress -o jsonpath='{.items[0].metadata.name}')"
  kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$pod" 19005:9901 >/dev/null 2>&1 &
  pf=$!
  sleep 4
  curl -s --max-time 8 -G --data-urlencode "filter=$1" http://127.0.0.1:19005/stats 2>/dev/null || true
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
}

# decision_export — GET /admin/v1/decisions from the control plane's admin API.
decision_export() {
  local pf
  kubectl --context "$KUBE_CONTEXT" -n "$INFRA_NS" port-forward deploy/edge-control-plane 19802:18002 >/dev/null 2>&1 &
  pf=$!
  sleep 4
  curl -sf --max-time 20 -H "X-Admin-Key: $CP_ADMIN_KEY" http://127.0.0.1:19802/admin/v1/decisions 2>/dev/null || true
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
}

phase31_agent_rate_limits() {
  section "PHASE 31 — per-agent rate limits and the decision log: a burst gets 429 and the exported chain verifies"
  local pgpod pod codes round1 hdrs i n200 first tdir verified line limited sa_alpha sa_beta
  sa_alpha="system:serviceaccount:$LOCKED_NS:rl-alpha"
  sa_beta="system:serviceaccount:$LOCKED_NS:rl-beta"

  section "the control plane: $RL_PER_MINUTE requests a minute per agent through edge-egress, and its admin API on"
  k -n "$INFRA_NS" create secret generic edge-cp-admin --from-literal=admin-api-key="$CP_ADMIN_KEY" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  # --reuse-values: every earlier phase's settings stay as they are.
  h upgrade edge-control-plane "$REPO_ROOT/deploy/helm/edge-control-plane" -n "$INFRA_NS" --reuse-values \
    --set egress.agentRequestsPerMinute="$RL_PER_MINUTE" --set adminApi.existingSecret=edge-cp-admin \
    --wait --timeout 200s >/dev/null || diag_fail edge-control-plane "$INFRA_NS"
  [ "$(k -n "$INFRA_NS" get deploy edge-control-plane \
      -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="EGRESS_AGENT_REQUESTS_PER_MINUTE")].value}')" = "$RL_PER_MINUTE" ] \
    || die "PHASE31: the control plane did not take EGRESS_AGENT_REQUESTS_PER_MINUTE=$RL_PER_MINUTE"
  k -n "$INFRA_NS" rollout status deploy/edge-control-plane --timeout=180s >/dev/null \
    || die "PHASE31: the control plane did not come back"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q >/dev/null \
    <<<"UPDATE egress_destinations SET keyless = true, updated_at = now() WHERE name = 'mock-llm';"

  section "three agent pods in $LOCKED_NS: rl-alpha-1 and rl-alpha-2 are one agent ($sa_alpha), rl-beta another"
  for pod in rl-alpha-1:rl-alpha rl-alpha-2:rl-alpha rl-beta:rl-beta; do
    k -n "$LOCKED_NS" delete pod "${pod%%:*}" --ignore-not-found --wait=true >/dev/null
    sed -e "s|__CURL__|$ATTACKER_IMAGE|" -e "s|__POD__|${pod%%:*}|" -e "s|__SA__|${pod#*:}|" \
      "$LOCAL_DIR/manifests/agent-ratelimit.yaml" | k apply -f - >/dev/null
  done
  for pod in rl-alpha-1 rl-alpha-2 rl-beta; do
    k -n "$LOCKED_NS" wait --for=condition=Ready "pod/$pod" --timeout=180s >/dev/null \
      || die "PHASE31: $pod did not become Ready"
  done
  ok "rl-alpha-1, rl-alpha-2 (ServiceAccount rl-alpha) and rl-beta (ServiceAccount rl-beta) running"

  section "edge-egress has the agent rate limit from the control plane"
  i=0
  until has "$(egress_stats '^egress_agent_rate_limit\.')" "egress_agent_rate_limit."; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || die "PHASE31: edge-egress never received the agent rate limit"
    sleep 2
  done
  ok "edge-egress counts egress_agent_rate_limit.*"

  section "RED — rl-alpha-1 sends a burst: $RL_PER_MINUTE requests are served, then 429"
  # The burst is twice the limit and two more, so it reaches 429 even if the
  # bucket refills (once a minute) during it. rl-alpha-2 asks right after, and
  # a refill between the two would hand rl-alpha tokens again: then both run
  # again, and only the first burst, from a full bucket, is counted.
  for i in 1 2 3; do
    codes="$(rl_burst rl-alpha-1 $((2 * RL_PER_MINUTE + 2)))"
    hdrs="$(rl_headers rl-alpha-2)"
    [ -n "${round1:-}" ] || round1="$codes"
    has "$codes" 429 && has "$hdrs" " 429" && break
    warn "round $i: rl-alpha-1 [$codes], rl-alpha-2 [$(printf '%s' "$hdrs" | head -1)] — a refill between them; again"
  done
  codes="$round1"
  echo "  rl-alpha-1: $codes"
  has "$codes" 429 || die "PHASE31 FAIL: a burst of $((2 * RL_PER_MINUTE + 2)) from rl-alpha-1 never got 429"
  first="${codes%%429*}"
  n200="$(printf '%s' "$first" | wc -w | tr -d ' ')"
  [ "$n200" -ge "$RL_PER_MINUTE" ] && [ "$first" = "$(printf '200 %.0s' $(seq 1 "$n200"))" ] \
    || die "PHASE31 FAIL: rl-alpha-1 was refused before its $RL_PER_MINUTE requests were served: $codes"
  ok "rl-alpha-1: $n200 served, then 429"

  section "RED — rl-alpha-2, the same agent from another pod: 429 at once, the bucket is the agent's"
  printf '%s\n' "$hdrs" | sed 's/^/    /'
  has "$hdrs" " 429" || die "PHASE31 FAIL: rl-alpha-2 (agent rl-alpha, a pod address of its own) was served"
  has "$hdrs" "x-ratelimit-limit: $RL_PER_MINUTE" && has "$hdrs" "retry-after: 60" \
    || die "PHASE31 FAIL: the 429 does not carry x-ratelimit-limit: $RL_PER_MINUTE and retry-after: 60"
  ok "rl-alpha-2: 429, x-ratelimit-limit: $RL_PER_MINUTE, retry-after: 60"

  section "GREEN — rl-beta, another agent, at the same moment: served from its own bucket"
  codes="$(rl_burst rl-beta 1)"
  [ "$codes" = "200 " ] || die "PHASE31 FAIL: rl-beta was not served while rl-alpha was limited: [$codes]"
  ok "rl-beta: 200"
  limited="$(egress_stats '^egress_agent_rate_limit\..*rate_limited$' | awk -F': ' '{print $2 + 0; exit}')"
  [ "${limited:-0}" -gt 0 ] || die "PHASE31 FAIL: edge-egress counted no rate-limited request"
  ok "edge-egress egress_agent_rate_limit rate_limited: $limited"

  section "the access log names the agent and the decision"
  # Envoy writes its access log out every few seconds, not per request.
  i=0
  while :; do
    line="$(k -n edge logs -l app.kubernetes.io/name=edge-egress --tail=2000 2>/dev/null \
      | grep -F "\"agent\":\"$sa_alpha\"" | grep -F '"status":429' | tail -1 || true)"
    [ -n "$line" ] && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || die "PHASE31 FAIL: no access-log line for $sa_alpha with status 429"
    sleep 2
  done
  printf '%s' "$line" | jq -e '.response_flags == "RL" and .response_code_details == "local_rate_limited"' >/dev/null \
    || die "PHASE31 FAIL: the 429's access-log line does not say rate limited: $line"
  echo "  $(printf '%s' "$line" | jq -c '{agent, status, response_flags, response_code_details, route, client_address}')"
  ok "edge-egress logged rl-alpha's 429 with its agent and RL / local_rate_limited"

  section "the decision log, exported from the admin API, holds rl-alpha's 429s and rl-beta's 200"
  tdir="$(mktemp -d)"
  i=0
  while :; do
    decision_export > "$tdir/decisions.ndjson"
    jq -e -s --arg a "$sa_alpha" --arg b "$sa_beta" '
      any(.[]; .agent == $a and .decision == "rate_limited" and .status == 429 and .reason == "local_rate_limited")
      and any(.[]; .agent == $b and .decision == "allowed" and .status == 200)' "$tdir/decisions.ndjson" >/dev/null 2>&1 && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || { tail -5 "$tdir/decisions.ndjson"; die "PHASE31 FAIL: the decision log never showed rl-alpha rate limited and rl-beta served"; }
    sleep 2
  done
  jq -c -s 'group_by(.decision) | map({decision: .[0].decision, records: length})' "$tdir/decisions.ndjson" | sed 's/^/  /'
  jq -e -s 'any(.[]; .decision == "denied" and .status == 407) and all(.[]; .node | startswith("edge-egress/"))' \
    "$tdir/decisions.ndjson" >/dev/null \
    || die "PHASE31 FAIL: the log is missing Phase 30's 407s, or holds a record from something other than edge-egress"
  ok "$(wc -l < "$tdir/decisions.ndjson" | tr -d ' ') records, Phase 30's 407s included, every one from an edge-egress Envoy"

  section "GREEN — the exported chain verifies"
  verified="$("$REPO_ROOT/scripts/verify-decisions.sh" "$tdir/decisions.ndjson")" \
    || die "PHASE31 FAIL: the exported decision log does not verify"
  echo "  $verified"
  has "$verified" "seq 1.." && has "$verified" "chained to 0000000000000000000000000000000000000000000000000000000000000000" \
    || die "PHASE31 FAIL: the export does not start at the beginning of the log"

  section "RED — the same export with one rate_limited record rewritten as allowed: it does not verify"
  awk -v a="$sa_alpha" 'done || index($0, "\"agent\":\"" a "\"") == 0 || index($0, "\"rate_limited\"") == 0 { print; next }
    { sub(/"decision":"rate_limited"/, "\"decision\":\"allowed\""); print; done = 1 }' \
    "$tdir/decisions.ndjson" > "$tdir/tampered.ndjson"
  ! cmp -s "$tdir/decisions.ndjson" "$tdir/tampered.ndjson" || die "PHASE31: the tampered copy is unchanged"
  if "$REPO_ROOT/scripts/verify-decisions.sh" "$tdir/tampered.ndjson" 2>"$tdir/err"; then
    die "PHASE31 FAIL: a rewritten record still verifies"
  fi
  echo "  $(cat "$tdir/err")"
  rm -rf "$tdir"

  ok "PHASE 31 — per-agent rate limits and the decision log: rl-alpha got 429 after $RL_PER_MINUTE (from both its pods) while rl-beta was served, edge-egress logged each decision with its agent, and the exported hash chain verifies — and stops verifying when one record is rewritten"
}

# ---- Phase 34 — every release passes its own `helm test` (B28.236) ----------------
# Each chart carries a test pod (templates/tests/) that reaches what the chart
# runs the way a client does: through its Service, past its NetworkPolicy, which
# lets exactly that pod in. It runs here, with every release installed and
# before Phase 32 takes the image registry away.
phase34_helm_test() {
  section "PHASE 34 — helm test, every release this run installed"
  local t rel ns
  for t in edge-control-plane:"$INFRA_NS" edge-issuer:"$INFRA_NS" auth-service:"$INFRA_NS" \
           edge-osb:"$INFRA_NS" edge-ratelimit:"$INFRA_NS" edge-secrets:"$INFRA_NS" \
           edge-proxy:edge edge-egress:edge edge-pki:cert-manager; do
    rel="${t%%:*}"; ns="${t#*:}"
    section "helm test $rel -n $ns"
    h test "$rel" -n "$ns" --logs --timeout 300s \
      || { k -n "$ns" get pod "$rel-test" -o wide 2>/dev/null || true; die "PHASE34 FAIL: helm test $rel did not pass"; }
    ok "$rel: helm test passed"
  done
  # Passed: clear them, so no later phase meets a Completed pod among a
  # release's (Phase 32 reads every auth-service pod's metrics).
  for ns in "$INFRA_NS" edge cert-manager; do
    k -n "$ns" delete pod -l app.kubernetes.io/component=helm-test --ignore-not-found --wait=true >/dev/null
  done
  ok "PHASE 34 — every release passes its own helm test: each chart's test pod reached its service through the Service and the chart's NetworkPolicy, and edge-pki's found its CAs Ready"
}

# ---- Phase 32 — no internet at run time (B28.231) -----------------------------
# A customer's cluster may have no route to the internet once it is installed.
# Cut it off: on every node every public address is unreachable, so neither a
# pod nor the node itself (nor hostNetwork Envoy) can send a packet outside the
# private ranges, and CoreDNS loses its upstream — a name outside the cluster
# gets NXDOMAIN, as from an internal resolver with no internet — and logs every
# query it is asked. Then restart every Edge workload from cold. They must come
# up and serve: auth-service loads each issuer's keys from inside the cluster
# (the edge-issuer, the API server's ServiceAccount keys, and the keys of an IdP
# outside the cluster, held in a Secret it re-reads, so rotating them is a
# Secret update), the OSB broker provisions a jwt route, and a token from each
# issuer is checked at the gateway. Over the whole run CoreDNS must log no query
# for a name outside the cluster. Two controls show the instruments can see: an
# outside name looked up on purpose is logged, and a packet to a public address
# has no way out.
AIRGAP_IDP="https://idp.corp.example"
AIRGAP_SECRET="idp-jwks"
AIRGAP_JWKS_FILE="/etc/auth-service/jwks/corp.json"
AIRGAP_SERVICE="e2e-offline"
AIRGAP_REFRESH_S=15
AIRGAP_STATE_DIR="${TMPDIR:-/tmp}/edge-airgap-$CLUSTER_NAME"
# Every release of the Edge charts: <namespace> <release>.
AIRGAP_RELEASES="$INFRA_NS edge-control-plane
$INFRA_NS edge-issuer
$INFRA_NS auth-service
$INFRA_NS edge-osb
edge edge-proxy
edge edge-egress"

b64url_e() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# airgap_jwk <key.pem> <kid> — the RSA public key as a JWKS document.
airgap_jwk() {
  local n
  n="$(openssl rsa -in "$1" -noout -modulus 2>/dev/null | sed 's/^Modulus=//' | xxd -r -p | b64url_e)"
  jq -cn --arg n "$n" --arg kid "$2" '{keys: [{kty: "RSA", use: "sig", alg: "RS256", kid: $kid, n: $n, e: "AQAB"}]}'
}

# airgap_token <key.pem> <kid> <aud> — an RS256 token from the outside IdP.
airgap_token() {
  local now hdr pl
  now="$(date +%s)"
  hdr="$(jq -cn --arg kid "$2" '{alg: "RS256", typ: "JWT", kid: $kid}' | b64url_e)"
  pl="$(jq -cn --arg iss "$AIRGAP_IDP" --arg aud "$3" --argjson now "$now" \
    '{iss: $iss, aud: $aud, sub: "alice@corp.example", email: "alice@corp.example", iat: $now, exp: ($now + 900)}' | b64url_e)"
  printf '%s.%s.%s' "$hdr" "$pl" "$(printf '%s.%s' "$hdr" "$pl" | openssl dgst -sha256 -sign "$1" | b64url_e)"
}

# airgap_cut — on every node, the internet made unreachable. Two unreachable
# /1 routes cover every address more specifically than the default route, and
# the private and link-local ranges go back via the node's gateway, so a pod,
# the node itself and hostNetwork Envoy all fail to reach a public address. The
# default route stays, as on a real air-gapped network: a Calico pod reaches
# its gateway 169.254.1.1 through the node's proxy ARP, which answers only for
# an address the node has a unicast route to.
AIRGAP_PRIVATE4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"
airgap_cut() {
  local n
  for n in $(kind get nodes --name "$CLUSTER_NAME"); do
    docker exec "$n" sh -c '
      gw="$(ip -4 route show default | awk "{print \$3; exit}")"
      [ -n "$gw" ] || exit 1
      for c in '"$AIRGAP_PRIVATE4"'; do ip route replace "$c" via "$gw"; done
      ip route replace unreachable 0.0.0.0/1
      ip route replace unreachable 128.0.0.0/1
      gw6="$(ip -6 route show default | awk "{print \$3; exit}")"
      if [ -n "$gw6" ]; then
        ip -6 route replace fc00::/7 via "$gw6"
        ip -6 route replace unreachable ::/1
        ip -6 route replace unreachable 8000::/1
      fi
      ! ip route get 1.1.1.1 >/dev/null 2>&1' \
      || die "PHASE32: could not cut $n off — it still has a route to 1.1.1.1, or no default route to keep"
  done
}

# airgap_lift — the routes airgap_cut added taken out, and the Corefile restored.
airgap_lift() {
  local n
  for n in $(kind get nodes --name "$CLUSTER_NAME"); do
    docker exec "$n" sh -c '
      for c in '"$AIRGAP_PRIVATE4"' 0.0.0.0/1 128.0.0.0/1; do ip route del "$c" 2>/dev/null; done
      for c in fc00::/7 ::/1 8000::/1; do ip -6 route del "$c" 2>/dev/null; done
      true' || true
  done
  if [ -s "$AIRGAP_STATE_DIR/Corefile" ]; then
    k -n kube-system create configmap coredns --from-file=Corefile="$AIRGAP_STATE_DIR/Corefile" \
      --dry-run=client -o yaml | k replace -f - >/dev/null
    k -n kube-system rollout restart deploy/coredns >/dev/null
    k -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null || true
    rm -f "${AIRGAP_STATE_DIR:?}/Corefile"
  fi
}

# airgap_queries — every name CoreDNS has been asked since it restarted
# offline, one per line.
airgap_queries() {
  local p
  for p in $(k -n kube-system get pod -l k8s-app=kube-dns -o jsonpath='{.items[*].metadata.name}'); do
    k -n kube-system logs "$p" 2>/dev/null
  done | sed -n 's/.*"[A-Z0-9]* IN \([^ ]*\) .*/\1/p'
}

# airgap_search_domains — the search domains a pod gets from its node, which
# kubelet appends after the cluster's own.
airgap_search_domains() {
  k -n tenant-secure exec minter -- cat /etc/resolv.conf 2>/dev/null \
    | awk '$1 == "search" { for (i = 2; i <= NF; i++) if ($i !~ /cluster\.local\.?$/) { sub(/\.$/, "", $i); print $i } }'
}

# airgap_classify <external|expansion> <search domain>... — the names among
# stdin of one class. In the cluster: under cluster.local, or the reverse lookup
# of a private address. An expansion: a name under cluster.local with one of
# the node's search domains appended, which a pod's resolver tries before the
# name as written. External: every other name.
airgap_classify() {
  local want="$1"; shift
  awk -v want="$want" -v doms="$*" '
    BEGIN { n = split(doms, d, " ") }
    /\.cluster\.local\.$/ { next }
    /\.in-addr\.arpa\.$/ {
      split($0, o, ".")
      if (o[4] == "10" || o[4] == "127" || (o[4] == "192" && o[3] == "168") || (o[4] == "172" && o[3] >= 16 && o[3] <= 31)) next
    }
    {
      cls = "external"
      for (i = 1; i <= n; i++) {
        suf = ".cluster.local." d[i] "."
        if (length($0) > length(suf) && substr($0, length($0) - length(suf) + 1) == suf) cls = "expansion"
      }
      if (cls == want) print
    }'
}

# airgap_gateway_diag <host> — what the gateway looks like when it does not
# answer: the codes on :80 and :443, what listens on the routable worker, the
# listeners its Envoy holds, and the last lines of the Envoy and control plane.
airgap_gateway_diag() {
  local ep
  echo "  :80 Host $1 -> $(gw80_code "$1"), :443 tenant-a.local -> $(gw_code tenant-a.local)"
  curl -sv --max-time 6 -H "Host: $1" http://127.0.0.1:80/ 2>&1 | tail -8 | sed 's/^/    /'
  k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o wide | sed 's/^/    /'
  echo "  listening on ${CLUSTER_NAME}-worker:"
  docker exec "${CLUSTER_NAME}-worker" sh -c 'ss -ltn | grep -E ":(80|443|9902) "' | sed 's/^/    /' || true
  ep="$(ep_pod_on "${CLUSTER_NAME}-worker")"
  if [ -n "$ep" ]; then
    echo "  $ep listeners and clusters:"
    envoy_config_dump "$ep" | jq -r '.configs[]? | (.dynamic_listeners[]? | "    listener \(.name) :\(.active_state.listener.address.socket_address.port_value // "?")"), (.dynamic_active_clusters[]? | "    cluster \(.cluster.name)")' 2>/dev/null | head -30
    k -n edge logs "$ep" --tail=15 2>/dev/null | cut -c1-240 | sed 's/^/    /'
  fi
  k -n "$INFRA_NS" logs deploy/edge-control-plane --tail=15 2>/dev/null | cut -c1-240 | sed 's/^/    /'
}

# airgap_metric <pod> <series> — one auth-service pod's value of a series.
airgap_metric() {
  kubectl --context "$KUBE_CONTEXT" -n "$INFRA_NS" port-forward "pod/$1" 19092:9090 >/dev/null 2>&1 &
  local pf=$! v="" i=0
  while [ "$i" -lt 10 ]; do
    v="$(curl -s --max-time 4 http://127.0.0.1:19092/metrics 2>/dev/null | awk -v s="$2" '$1 == s {print $2}')"
    [ -n "$v" ] && break
    i=$((i + 1)); sleep 1
  done
  kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  printf '%s' "${v:-0}"
}

phase32_no_internet() {
  section "PHASE 32 — no internet at run time: every node cut off, the stack restarted cold, and not one DNS query for a name outside the cluster"
  local UMAIL="dev@edge.local" UPASS="devpassword-abc12345"
  local ISS="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"
  local tdir aud issuers r sip n ns rel w x wl out c tok1 tok2 itok i pods p ext all ok_refresh fail_refresh ok0 fail0 doms nexp
  need xxd
  tdir="$(mktemp -d)"
  trap 'airgap_lift' EXIT

  section "an IdP outside the cluster: its keys held in Secret $AIRGAP_SECRET, auth-service told to read them from there"
  openssl genrsa -out "$tdir/corp-1.pem" 2048 2>/dev/null
  openssl genrsa -out "$tdir/corp-2.pem" 2048 2>/dev/null
  airgap_jwk "$tdir/corp-1.pem" corp-1 > "$tdir/corp.json"
  k -n "$INFRA_NS" create secret generic "$AIRGAP_SECRET" --from-file=corp.json="$tdir/corp.json" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  issuers="$(k -n "$INFRA_NS" get secret auth-service-secrets -o jsonpath='{.data.JWT_ISSUERS}' | openssl base64 -d -A 2>/dev/null || true)"
  issuers="$(printf '%s' "${issuers:-[]}" | jq -c --arg iss "$AIRGAP_IDP" --arg f "$AIRGAP_JWKS_FILE" \
    '[.[] | select(.issuer != $iss)] + [{issuer: $iss, jwks_file: $f}]')"
  k -n "$INFRA_NS" patch secret auth-service-secrets --type merge \
    -p "$(jq -cn --arg v "$issuers" '{stringData: {JWT_ISSUERS: $v}}')" >/dev/null
  h upgrade auth-service "$REPO_ROOT/deploy/helm/auth-service" -n "$INFRA_NS" --reuse-values \
    --set jwksFiles.existingSecret="$AIRGAP_SECRET" --set config.jwksRefreshSeconds="$AIRGAP_REFRESH_S" \
    --wait --timeout 180s >/dev/null || die "PHASE32: auth-service did not upgrade with jwksFiles"
  aud="$(k -n "$INFRA_NS" get secret auth-service-secrets -o jsonpath='{.data.JWT_AUDIENCE}' | openssl base64 -d -A)"
  ok "JWT_ISSUERS now ends with {issuer: $AIRGAP_IDP, jwks_file: $AIRGAP_JWKS_FILE}; keys re-read every ${AIRGAP_REFRESH_S}s"

  # The minter pod (Phase 25) asks the edge-issuer for a token from inside the cluster.
  k apply -f "$LOCAL_DIR/manifests/secure-backend.yaml" >/dev/null
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=120s >/dev/null
  k apply -f "$LOCAL_DIR/manifests/osb-stub.yaml" >/dev/null
  wait_rollout deploy/echo osb-stub 120s >/dev/null
  sip="$(k -n osb-stub get svc echo -o jsonpath='{.spec.clusterIP}')"

  section "cut the internet: every public address unreachable from every node, CoreDNS with no upstream and every query logged"
  airgap_cut
  for n in $(kind get nodes --name "$CLUSTER_NAME"); do
    echo "  $n: $(docker exec "$n" sh -c 'ip route get 1.1.1.1 2>&1 | head -1')"
  done
  mkdir -p "$AIRGAP_STATE_DIR"
  if [ ! -s "$AIRGAP_STATE_DIR/Corefile" ]; then
    k -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' > "$AIRGAP_STATE_DIR/Corefile"
  fi
  # The cluster's zones keep their server block, with no forward (and no loop
  # check, which only guards a forward) and every query logged. Every other
  # name gets NXDOMAIN from a catch-all block, as from an internal resolver that
  # knows no name outside the cluster.
  awk '
    NR == 1 && /^\.:53[[:space:]]*\{/ { print "cluster.local:53 in-addr.arpa:53 ip6.arpa:53 {"; next }
    /^[[:space:]]*forward[[:space:]]/ { skip = /\{[[:space:]]*$/; next }
    skip { if (/^[[:space:]]*\}[[:space:]]*$/) skip = 0; next }
    /^[[:space:]]*loop[[:space:]]*$/ { next }
    /^[[:space:]]*errors[[:space:]]*$/ { print; sub(/errors/, "log"); print; next }
    { print }
    END {
      print ".:53 {"
      print "    errors"
      print "    log"
      print "    template ANY ANY {"
      print "       rcode NXDOMAIN"
      print "       authority \"{{ .Zone }} 60 IN SOA ns.offline. hostmaster.offline. (1 60 60 60 60)\""
      print "    }"
      print "}"
    }' "$AIRGAP_STATE_DIR/Corefile" > "$tdir/Corefile"
  ! has "$(cat "$tdir/Corefile")" forward || die "PHASE32: the offline Corefile still forwards"
  has "$(head -1 "$tdir/Corefile")" "cluster.local:53" || die "PHASE32: the Corefile does not start with the .:53 block this phase rewrites"
  k -n kube-system create configmap coredns --from-file=Corefile="$tdir/Corefile" --dry-run=client -o yaml | k replace -f - >/dev/null
  k -n kube-system rollout restart deploy/coredns >/dev/null
  k -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null || die "PHASE32: CoreDNS did not come back offline"
  ok "CoreDNS restarted with no upstream: cluster names served, every other name NXDOMAIN, every query logged"

  section "restart every Edge workload from cold, offline"
  wl=""
  while read -r ns rel; do
    w="$(k -n "$ns" get deploy,daemonset -l "app.kubernetes.io/instance=$rel" -o name)"
    [ -n "$w" ] || die "PHASE32: release $rel runs no workload in $ns"
    for x in $w; do wl="$wl$ns $x"$'\n'; done
  done <<<"$AIRGAP_RELEASES"
  while read -r ns w; do
    [ -n "$w" ] && k -n "$ns" rollout restart "$w" >/dev/null
  done <<<"$wl"
  while read -r ns w; do
    [ -n "$w" ] || continue
    k -n "$ns" rollout status "$w" --timeout=240s >/dev/null \
      || { k -n "$ns" describe "$w" | tail -20; die "PHASE32 FAIL: $ns/$w did not come back with no internet"; }
    ok "$ns/$w Ready"
  done <<<"$wl"

  # Key-refresh counters once the restart has settled (no issuer pod is
  # terminating any more); the check below compares against them.
  pods="$(k -n "$INFRA_NS" get pod -l app.kubernetes.io/instance=auth-service -o jsonpath='{.items[*].metadata.name}')"
  for p in $pods; do
    echo "$p $(airgap_metric "$p" 'jwks_refresh_total{result="success"}') $(airgap_metric "$p" 'jwks_refresh_total{result="failure"}')"
  done > "$tdir/refresh0"

  section "auth-service loaded every issuer's keys from inside the cluster"
  out="$(k -n "$INFRA_NS" logs deploy/auth-service --tail=-1 2>/dev/null | grep '"trusting issuer"' || true)"
  printf '%s\n' "$out" | jq -r '.fields | "    \(.issuer)  <-  \(.jwks)"' 2>/dev/null || printf '%s\n' "$out"
  has "$out" "file:$AIRGAP_JWKS_FILE" || die "PHASE32 FAIL: auth-service did not load $AIRGAP_IDP's keys from $AIRGAP_JWKS_FILE"
  has "$out" "edge-issuer.${INFRA_NS}.svc.cluster.local" || die "PHASE32 FAIL: auth-service did not load the edge-issuer's keys"

  section "the OSB broker provisions '$AIRGAP_SERVICE' (jwt by default), and the gateway checks each issuer's token"
  r="$(osb_call DELETE "/v1/services/$AIRGAP_SERVICE")"
  if [ "${r%% *}" = 202 ]; then osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"; fi
  r="$(osb_call POST /v1/services \
    "{\"name\":\"$AIRGAP_SERVICE\",\"team\":\"$OSB_TEAM\",\"host\":\"$sip\",\"port\":5678,\"protocol\":\"HTTP\"}")"
  [ "${r%% *}" = 202 ] || die "PHASE32 FAIL: the broker did not accept the service offline (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  i=0; c=""
  while [ "$i" -lt 30 ]; do
    c="$(gw80_code "$sip")"; [ "$c" = 401 ] && break
    i=$((i + 1)); sleep 2
  done
  [ "$c" = 401 ] || { airgap_gateway_diag "$sip"; die "PHASE32 FAIL: no token got $c, want 401 (the route is not published, or not gated)"; }
  ok "no token -> 401"
  itok="$(k -n tenant-secure exec minter -- curl -sk --max-time 6 -X POST "$ISS/login" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$UMAIL\",\"password\":\"$UPASS\"}" 2>/dev/null \
    | jq -r '.access_token // empty' 2>/dev/null || true)"
  [ -n "$itok" ] || die "PHASE32 FAIL: the edge-issuer did not mint a token offline"
  c="$(gw80_code "$sip" -H "Authorization: Bearer $itok")"
  [ "$c" = 200 ] || { airgap_gateway_diag "$sip"; die "PHASE32 FAIL: an edge-issuer token got $c, want 200"; }
  ok "edge-issuer token -> 200"
  tok1="$(airgap_token "$tdir/corp-1.pem" corp-1 "$aud")"
  c="$(gw80_code "$sip" -H "Authorization: Bearer $tok1")"
  [ "$c" = 200 ] || die "PHASE32 FAIL: a token from $AIRGAP_IDP (key corp-1, held in the Secret) got $c, want 200"
  ok "$AIRGAP_IDP token (corp-1) -> 200, its keys read from the Secret"

  section "rotate $AIRGAP_IDP's key by updating the Secret alone: corp-2 in, corp-1 out"
  airgap_jwk "$tdir/corp-2.pem" corp-2 > "$tdir/corp.json"
  k -n "$INFRA_NS" create secret generic "$AIRGAP_SECRET" --from-file=corp.json="$tdir/corp.json" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  tok2="$(airgap_token "$tdir/corp-2.pem" corp-2 "$aud")"
  i=0; c=""
  while [ "$i" -lt 60 ]; do
    c="$(gw80_code "$sip" -H "Authorization: Bearer $tok2")"
    [ "$c" = 200 ] && [ "$(gw80_code "$sip" -H "Authorization: Bearer $tok1")" = 401 ] && break
    i=$((i + 1)); sleep 3
  done
  [ "$c" = 200 ] || die "PHASE32 FAIL: a corp-2 token still got $c after the Secret was updated"
  [ "$(gw80_code "$sip" -H "Authorization: Bearer $tok1")" = 401 ] || die "PHASE32 FAIL: the rotated-out corp-1 key is still trusted"
  ok "corp-2 -> 200 and corp-1 -> 401 after ~$((i * 3))s — rotated with no restart and no network"

  section "every key refresh since the restart settled succeeded, offline"
  while read -r p ok0 fail0; do
    ok_refresh="$(airgap_metric "$p" 'jwks_refresh_total{result="success"}')"
    fail_refresh="$(airgap_metric "$p" 'jwks_refresh_total{result="failure"}')"
    echo "  $p: jwks_refresh_total success $ok0 -> $ok_refresh, failure $fail0 -> $fail_refresh"
    [ $(( ${ok_refresh%%.*} - ${ok0%%.*} )) -ge 3 ] \
      || die "PHASE32 FAIL: $p did not refresh all three issuers' keys while offline"
    [ "${fail_refresh%%.*}" = "${fail0%%.*}" ] \
      || die "PHASE32 FAIL: $p failed a key refresh with no internet"
  done < "$tdir/refresh0"

  section "THE VERDICT — every name CoreDNS was asked since it went offline"
  all="$(airgap_queries | grep . || true)"
  doms="$(airgap_search_domains | tr '\n' ' ')"
  ext="$(printf '%s\n' "$all" | grep . | airgap_classify external $doms | sort | uniq -c | sort -rn || true)"
  nexp="$(printf '%s\n' "$all" | grep . | airgap_classify expansion $doms | grep -c . || true)"
  echo "  $(printf '%s\n' "$all" | grep -c .) queries, $(printf '%s\n' "$all" | grep . | sort -u | wc -l | tr -d ' ') distinct names; the most asked:"
  printf '%s\n' "$all" | grep . | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
  if [ "${nexp:-0}" -gt 0 ]; then
    echo "  $nexp of them are a cluster.local name with the node's search domain (${doms% }) appended — a pod's resolver tries that before the name as written; none names a host outside the cluster"
  fi
  [ "$(printf '%s\n' "$all" | grep -c .)" -gt 0 ] || die "PHASE32 FAIL: CoreDNS logged no queries at all, so its silence proves nothing"
  [ -z "$ext" ] || { echo "  names outside the cluster:"; printf '%s\n' "$ext" | sed 's/^/    /'; die "PHASE32 FAIL: with no internet, a workload still looked up a name outside the cluster"; }
  ok "0 queries for a name outside the cluster"

  section "CONTROL — the instruments see: an outside name is logged, a public address has no route"
  out="$(k -n tenant-secure exec minter -- curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://api.openai.com/ 2>&1 || true)"
  i=0
  until has "$(airgap_queries | airgap_classify external $doms)" "api.openai.com."; do
    i=$((i + 1)); [ "$i" -lt 10 ] || die "PHASE32: CoreDNS did not log a lookup of api.openai.com — the verdict above could not have seen one"
    sleep 1
  done
  ok "curl https://api.openai.com from a pod: no answer (HTTP ${out:-000}), and CoreDNS logged api.openai.com. as outside the cluster"
  out="$(k -n tenant-secure exec minter -- sh -c 'curl -s -o /dev/null --max-time 5 http://1.1.1.1/; echo "curl-exit=$?"' 2>&1 || true)"
  ! has "$out" "curl-exit=0" || die "PHASE32: a pod reached 1.1.1.1 — the cluster is not cut off"
  ok "curl http://1.1.1.1 from a pod, no DNS involved: $(printf '%s\n' "$out" | tail -1) — no way out"

  section "lift: the routes and the Corefile put back; '$AIRGAP_SERVICE' deprovisioned"
  r="$(osb_call DELETE "/v1/services/$AIRGAP_SERVICE")"
  if [ "${r%% *}" = 202 ]; then osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"; fi
  trap - EXIT
  airgap_lift
  rm -rf "${tdir:?}"
  ok "PHASE 32 — no internet at run time: with no route to a public address and no upstream DNS, every Edge workload restarted cold and served; auth-service read the edge-issuer's, the API server's and an outside IdP's keys from inside the cluster (the IdP's rotated by a Secret update), and CoreDNS logged 0 queries for a name outside the cluster"
}

# ---- Phase 33 — KEK rotation: SDS still serves the cert (B28.234) -------------
# The custodian seals every key under SECRET_KEK (enc:v2:<kid>:...). Rotating it:
# both services get the new KEK as SECRET_KEK and the old one as
# SECRET_KEK_PREVIOUS, `secrets reseal` moves every key onto the new KEK, and the
# old one is dropped. Measured on a cert written through the custodian and served
# by SNI on Phase 20's shared port: once the old KEK is gone, a restarted control
# plane (Ready only after its first publish, which opens every key) serves a
# fresh Envoy the same cert. Real-cluster steps: docs/kek-rotation.md.
ROT_HOST="rotate.local"

# custodian_reseal — POST /v1/reseal on edge-secrets as the operator from Phase
# 5's admin PKI. Echoes the JSON answer, then "http=<code>" on its own line.
custodian_reseal() {
  local pki="$LOCAL_DIR/.pki-bootstrap" pf out
  kubectl --context "$KUBE_CONTEXT" -n "$INFRA_NS" port-forward svc/edge-secrets 18082:8082 >/dev/null 2>&1 &
  pf=$!
  sleep 4
  out="$(curl -s -w '\nhttp=%{http_code}' --max-time 30 -X POST \
    --cacert "$pki/admin-ca.crt" --cert "$pki/operator.crt" --key "$pki/operator.key" \
    "https://localhost:18082/v1/reseal" 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
  printf '%s' "$out"
}

phase33_kek_rotation() {
  section "PHASE 33 — KEK rotation: every key re-sealed under a new KEK, the old one dropped, and SDS still serves the cert"
  local pki="$LOCAL_DIR/.pki-bootstrap" tmp node ip pgpod body code out res old_kek new_kek old_kid new_kid left start_before old_pod new_pod i=0 s
  node="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].spec.nodeName}')"
  ip="$(k get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  [ -n "$ip" ] || die "PHASE33: no edge-proxy node IP"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  psql_edge() { k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -qtA -c "$1"; }
  # rot_served — the HTTPS answer for $ROT_HOST on the shared port, retried until
  # it presents its own cert and reaches its backend.
  rot_served() {
    local out n=0
    while :; do
      out="$(sni_get "$ip" "$ROT_HOST")"
      has "$out" "CN=$ROT_HOST" && has "$out" "TENANT-A-BACKEND" && { printf '%s' "$out"; return; }
      n=$((n + 1)); [ "$n" -lt 30 ] || { printf '%s\n' "$out" | tail -15 >&2; die "PHASE33 FAIL: $ROT_HOST was not served its cert ($1)"; }
      sleep 2
    done
  }
  restart_kek_holders() {
    k -n "$INFRA_NS" rollout restart deploy/edge-control-plane deploy/edge-secrets >/dev/null
    wait_rollout deploy/edge-control-plane "$INFRA_NS" 240s >/dev/null || die "PHASE33 FAIL: the control plane did not come back Ready ($1)"
    wait_rollout deploy/edge-secrets "$INFRA_NS" 240s >/dev/null || die "PHASE33 FAIL: the custodian did not come back Ready ($1)"
  }

  section "a cert for $ROT_HOST written through the custodian, routed on the shared SNI port :$SNI_PORT"
  tmp="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$ROT_HOST" \
    -keyout "$tmp/rot.key" -out "$tmp/rot.crt" >/dev/null 2>&1 || die "openssl could not mint $ROT_HOST's cert"
  body="$(jq -n --rawfile c "$tmp/rot.crt" --rawfile k "$tmp/rot.key" '{kind: "tls_certificate", cert_pem: $c, key_pem: $k}')"
  rm -rf "$tmp"
  code="$(custodian_put rotate-cert "$body")"
  [ "$code" = 200 ] || die "PHASE33: the custodian did not accept $ROT_HOST's cert (HTTP $code)"
  psql_edge "INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,tls_secret_name,deleted_at)
VALUES ('rotate','rotate','sni-shared-https',ARRAY['$ROT_HOST']::text[],'/','tenant-a',30,'none','rotate-cert',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,tls_secret_name=EXCLUDED.tls_secret_name,
  cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;" >/dev/null
  old_kid="$(psql_edge "SELECT split_part(key_pem, ':', 3) FROM secrets WHERE name='rotate-cert' AND key_pem LIKE 'enc:v2:%'")"
  [ -n "$old_kid" ] || die "PHASE33 FAIL: rotate-cert's key is not sealed enc:v2:<kid>:... at rest"
  out="$(rot_served "before the rotation")"
  start_before="$(printf '%s\n' "$out" | grep -m1 'start date:' | sed 's/^[* ]*//')"
  ok "rotate-cert sealed under KEK $old_kid; $ROT_HOST served CN=$ROT_HOST ($start_before) -> TENANT-A-BACKEND"

  section "rotate: a new SECRET_KEK, the old one as SECRET_KEK_PREVIOUS, in both services' Secrets; both restarted"
  old_kek="$(k -n "$INFRA_NS" get secret edge-secrets-config -o jsonpath='{.data.SECRET_KEK}' | base64 -d)"
  new_kek="$(openssl rand -base64 32)"
  for s in edge-control-plane-postgres edge-secrets-config; do
    k -n "$INFRA_NS" patch secret "$s" --type merge \
      -p "$(jq -nc --arg n "$new_kek" --arg o "$old_kek" '{stringData: {SECRET_KEK: $n, SECRET_KEK_PREVIOUS: $o}}')" >/dev/null
  done
  restart_kek_holders "holding the new KEK and the old"
  rot_served "mid-rotation" >/dev/null
  ok "mid-rotation: both services hold the new KEK and the old; $ROT_HOST still served"

  section "re-seal through the custodian: every key moved onto the new KEK"
  res="$(custodian_reseal)"
  has "$res" "http=200" || die "PHASE33 FAIL: the re-seal was refused: $res"
  res="$(printf '%s\n' "$res" | sed '$d')"
  new_kid="$(printf '%s' "$res" | jq -r '.key_id')"
  echo "  POST /v1/reseal -> $res"
  [ -n "$new_kid" ] && [ "$new_kid" != "$old_kid" ] || die "PHASE33 FAIL: the re-seal answered KEK '$new_kid', not a new one"
  [ "$(printf '%s' "$res" | jq -r '.resealed')" -ge 1 ] || die "PHASE33 FAIL: the re-seal moved no key"
  left="$(psql_edge "SELECT count(*) FROM secrets WHERE key_pem IS NOT NULL AND key_pem <> '' AND key_pem NOT LIKE 'enc:v2:$new_kid:%'")"
  [ "$left" = 0 ] || die "PHASE33 FAIL: $left key(s) are not sealed under the new KEK $new_kid"
  ok "every key at rest is enc:v2:$new_kid:... — rotate-cert moved from $old_kid"

  section "drop the old KEK: SECRET_KEK_PREVIOUS removed from both Secrets; both restarted"
  for s in edge-control-plane-postgres edge-secrets-config; do
    k -n "$INFRA_NS" patch secret "$s" --type json -p '[{"op":"remove","path":"/data/SECRET_KEK_PREVIOUS"}]' >/dev/null
  done
  # Phase 5 re-applies the KEK from this file on a re-run: keep it the live one.
  printf '%s' "$new_kek" > "$pki/secret_kek.b64"
  restart_kek_holders "holding the new KEK alone"
  ok "the control plane and the custodian are Ready holding only KEK $new_kid"

  section "a fresh Envoy on $node is served the cert by a control plane that holds only the new KEK"
  old_pod="$(ep_pod_on "$node")"
  k -n edge delete pod "$old_pod" --wait=true >/dev/null
  while :; do
    new_pod="$(ep_pod_on "$node")"
    [ -n "$new_pod" ] && [ "$new_pod" != "$old_pod" ] && k -n edge wait --for=condition=Ready "pod/$new_pod" --timeout=10s >/dev/null 2>&1 && break
    i=$((i + 1)); [ "$i" -lt 30 ] || die "PHASE33: no new edge-proxy became Ready on $node"
    sleep 3
  done
  out="$(rot_served "after the rotation, fresh Envoy $new_pod")"
  has "$out" "$start_before" || { printf '%s\n' "$out" | tail -15; die "PHASE33 FAIL: $ROT_HOST was served a different cert after the rotation"; }
  ok "PHASE 33 — KEK rotated: every key re-sealed under $new_kid, $old_kid dropped, and a fresh Envoy is served $ROT_HOST's same cert over SDS"
}

# ---- Phase 35 — an expired licence warns and drops nothing (B28.238) --------
# The Talyvor Edge licence is advisory (docs/licence.md): the control plane checks
# it offline and exports edge_licence_valid, and nothing it serves depends on it.
# The licences here are minted with openssl from a key made for this run (the
# token format is docs/licence.md's), trusted through licence.publicKeys.
licence_b64url() { openssl base64 -A | tr -d '=' | tr '+/' '-_'; }

# mint_licence <key.pem> <id> <expires-unix> — a licence token signed by key.pem.
mint_licence() {
  local key="$1" id="$2" exp="$3" payload signed tmp
  payload="$(jq -nc --arg id "$id" --argjson exp "$exp" \
    '{id: $id, licensee: "Kind E2E", plan: "enterprise", issued_at: (now | floor | todate), expires_at: ($exp | todate)}' \
    | tr -d '\n' | licence_b64url)"
  signed="talyvor-edge-licence-v1.$payload"
  tmp="$(mktemp)"
  printf '%s' "$signed" > "$tmp"
  printf '%s.%s' "$signed" "$(openssl pkeyutl -sign -inkey "$key" -rawin -in "$tmp" | licence_b64url)"
  rm -f "$tmp"
}

# metric_of <metrics-text> <name> — the value of an unlabelled series.
metric_of() { printf '%s\n' "$1" | awk -v n="$2" '$1 == n {print $2}' | tail -1; }

phase35_licence() {
  section "PHASE 35 — offline licence: an expired licence reads edge_licence_valid 0, is warned about, and traffic still returns 200"
  local tdir pub now exp_at m v e i host
  tdir="$(mktemp -d)"
  openssl genpkey -algorithm ed25519 -out "$tdir/licence.pem" 2>/dev/null || die "PHASE35: openssl could not make an Ed25519 key"
  pub="$(openssl pkey -in "$tdir/licence.pem" -pubout -outform DER | tail -c 32 | openssl base64 -A)"
  now="$(date +%s)"

  section "red-first: a licence valid for a day reads edge_licence_valid 1"
  apply_secret "$INFRA_NS" generic edge-licence \
    --from-literal=licence="$(mint_licence "$tdir/licence.pem" lic_kind_valid $((now + 86400)))" >/dev/null
  h upgrade edge-control-plane "$REPO_ROOT/deploy/helm/edge-control-plane" -n "$INFRA_NS" \
    -f "$LOCAL_DIR/values/values-control-plane.yaml" \
    --set licence.existingSecret=edge-licence --set "licence.publicKeys[0]=$pub" \
    --wait --timeout 200s >/dev/null || die "PHASE35: the control plane did not upgrade with the licence"
  i=0
  while :; do
    m="$(cp_scrape)"; v="$(metric_of "$m" edge_licence_valid)"
    [ "$v" = 1 ] && break
    i=$((i + 1)); [ "$i" -lt 10 ] || die "PHASE35 FAIL: a valid licence reads edge_licence_valid=${v:-<absent>}, not 1"
    sleep 3
  done
  ok "edge_licence_valid 1 for lic_kind_valid"

  section "the licence is replaced by one that expired yesterday — no restart"
  exp_at=$((now - 86400))
  apply_secret "$INFRA_NS" generic edge-licence \
    --from-literal=licence="$(mint_licence "$tdir/licence.pem" lic_kind_expired "$exp_at")" >/dev/null
  # The kubelet refreshes the mounted Secret within about a minute; each scrape re-reads it.
  i=0
  while :; do
    m="$(cp_scrape)"; v="$(metric_of "$m" edge_licence_valid)"; e="$(metric_of "$m" edge_licence_expiry_timestamp_seconds)"
    [ "$v" = 0 ] && awk -v a="$e" -v b="$exp_at" 'BEGIN{exit !(a == b)}' && break
    i=$((i + 1)); [ "$i" -lt 60 ] || die "PHASE35 FAIL: 3 minutes after the expired licence went in, edge_licence_valid=${v:-<absent>} expiry=${e:-<absent>} (want 0 and $exp_at)"
    sleep 3
  done
  ok "edge_licence_valid 0, edge_licence_expiry_timestamp_seconds $e (yesterday)"
  for host in tenant-a.local tenant-b.local; do
    [ "$(gw_code "$host")" = 200 ] || die "PHASE35 FAIL: $host did not return 200 with an expired licence"
  done
  ok "tenant-a.local and tenant-b.local still 200"
  # Each replica re-checks once a minute and warns when the state changes.
  cp_logs() { k -n "$INFRA_NS" logs -l app.kubernetes.io/name=edge-control-plane --tail=-1 --since=10m 2>/dev/null | grep -F 'licence EXPIRED' | grep -F lic_kind_expired; }
  i=0
  until cp_logs >/dev/null; do
    i=$((i + 1)); [ "$i" -lt 60 ] || die "PHASE35 FAIL: the control plane logged no warning for the expired licence"
    sleep 3
  done
  ok "the control plane warned: $(cp_logs | tail -1 | jq -r '.msg')"

  section "a cold start with the expired licence: control plane restarted, edge-proxy rolled for a fresh xDS connection"
  k -n "$INFRA_NS" rollout restart deploy/edge-control-plane >/dev/null
  wait_rollout deploy/edge-control-plane "$INFRA_NS" 240s >/dev/null || die "PHASE35 FAIL: the control plane did not come back Ready with an expired licence"
  k -n edge rollout restart ds/edge-proxy >/dev/null
  wait_rollout ds/edge-proxy edge 240s >/dev/null || die "PHASE35: edge-proxy did not roll"
  for host in tenant-a.local tenant-b.local; do
    i=0
    until [ "$(gw_code "$host")" = 200 ]; do
      i=$((i + 1)); [ "$i" -lt 30 ] || die "PHASE35 FAIL: $host is not served by a fresh Envoy from a control plane holding an expired licence"
      sleep 2
    done
  done
  m="$(cp_scrape)"; v="$(metric_of "$m" edge_licence_valid)"
  [ "$v" = 0 ] || die "PHASE35 FAIL: after the restart edge_licence_valid=${v:-<absent>}, not 0"
  rm -rf "${tdir:?}"
  ok "PHASE 35 — with an expired licence edge_licence_valid is 0 and the control plane warns, and both tenants return 200, through a cold restart and a fresh Envoy"
}

# ---- Phase 36 — an agent's own ServiceAccount token passes the gateway (B28.443)
# An agent calls an OSB service with nothing but a ServiceAccount token the
# kubelet projected for the gateway's audience. auth-service reads the cluster's
# signing keys from the API server itself: its JWT_ISSUERS entry names the API
# server's CA (ca_file) and the pod's own token (token_file), so the keys need no
# anonymous access — Phase 30's grant of them to system:unauthenticated is
# removed first. The same agent's token for another audience gets 401.
SA_AGENT_NS="agents-sa"
OSB_SA_SERVICE="e2e-sa"

# sa_agent_curl <gateway|other> <host> <node-ip> — from agent-sa, a request to
# <host> on that node's gateway :80 with the token projected under
# /var/run/secrets/talyvor/<gateway|other> as its bearer. Echoes the body, then
# the HTTP code on its own line.
sa_agent_curl() {
  k -n "$SA_AGENT_NS" exec agent-sa -- sh -c 'curl -s --max-time 6 -w "\n%{http_code}" -H "Host: $2" \
    -H "Authorization: Bearer $(cat "/var/run/secrets/talyvor/$1/token")" "http://$3:80/"' \
    _ "$1" "$2" "$3" 2>/dev/null || true
}

phase36_sa_token_gateway() {
  section "PHASE 36 — an agent's own ServiceAccount token passes the gateway; its token for another audience does not"
  local aud iss api code issuers out claims sip node gwip r i

  aud="$(k -n "$INFRA_NS" get secret auth-service-secrets -o jsonpath='{.data.JWT_AUDIENCE}' | openssl base64 -d -A)"
  iss="$(k get --raw /.well-known/openid-configuration | jq -r .issuer)"
  [ -n "$aud" ] && [ -n "$iss" ] && [ "$iss" != null ] \
    || die "PHASE36: no JWT_AUDIENCE, or the API server publishes no ServiceAccount issuer"

  section "CONTROL — the API server's keys closed to anonymous callers (Phase 30 opened them)"
  k delete clusterrolebinding edge-sa-issuer-discovery --ignore-not-found >/dev/null
  api="$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  i=0
  while :; do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "$api/openid/v1/jwks" || true)"
    [ "$code" = 401 ] || [ "$code" = 403 ] && break
    i=$((i + 1))
    [ "$i" -lt 15 ] || die "PHASE36: an anonymous GET $api/openid/v1/jwks still gets $code, so a fetch without a token would pass too"
    sleep 2
  done
  ok "anonymous GET /openid/v1/jwks -> $code"

  section "auth-service trusts $iss for audience $aud, fetching its keys with its own ServiceAccount token"
  issuers="$(k -n "$INFRA_NS" get secret auth-service-secrets -o jsonpath='{.data.JWT_ISSUERS}' | openssl base64 -d -A 2>/dev/null || true)"
  issuers="$(printf '%s' "${issuers:-[]}" | jq -c --arg iss "$iss" --arg aud "$aud" \
    '[.[] | select(.issuer != $iss)] + [{issuer: $iss, audience: $aud,
      jwks_url: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
      ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
      token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"}]')"
  k -n "$INFRA_NS" patch secret auth-service-secrets --type merge \
    -p "$(jq -cn --arg v "$issuers" '{stringData: {JWT_ISSUERS: $v}}')" >/dev/null
  k -n "$INFRA_NS" rollout restart deploy/auth-service >/dev/null
  k -n "$INFRA_NS" rollout status deploy/auth-service --timeout=180s >/dev/null \
    || { k -n "$INFRA_NS" logs deploy/auth-service --tail=30 || true; die "PHASE36 FAIL: auth-service could not load $iss's keys with its own token"; }
  # logs deploy/ may read a pod of the old ReplicaSet until it has terminated.
  i=0
  while :; do
    out="$(k -n "$INFRA_NS" logs deploy/auth-service --tail=-1 2>/dev/null | grep '"trusting issuer"' || true)"
    has "$out" "\"issuer\":\"$iss\"" && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$out"; die "PHASE36 FAIL: the restarted auth-service does not trust $iss"; }
    sleep 2
  done
  ok "auth-service restarted and loaded $iss's keys from an API server that refuses anonymous callers"

  section "agent-sa in $SA_AGENT_NS: tokens projected for $aud and for billing.internal, nothing else"
  k delete namespace "$SA_AGENT_NS" --ignore-not-found --wait=true >/dev/null
  sed -e "s|__CURL__|$ATTACKER_IMAGE|" -e "s|__AUD__|$aud|" "$LOCAL_DIR/manifests/agent-sa-token.yaml" | k apply -f - >/dev/null
  k -n "$SA_AGENT_NS" wait --for=condition=Ready pod/agent-sa --timeout=180s >/dev/null \
    || die "PHASE36: agent-sa did not become Ready"
  out="$(k -n "$SA_AGENT_NS" exec agent-sa -- cat /var/run/secrets/talyvor/gateway/token)"
  claims="$(b64url_d "$(printf '%s' "$out" | cut -d. -f2)")"
  printf '%s' "$claims" | jq -e --arg iss "$iss" --arg aud "$aud" --arg sub "system:serviceaccount:$SA_AGENT_NS:agent-sa" \
    '.iss == $iss and .sub == $sub and ([.aud] | flatten | any(. == $aud))' >/dev/null \
    || die "PHASE36: agent-sa's projected token is not the kubelet's token for $aud: $claims"
  echo "  agent-sa's gateway token: $(printf '%s' "$claims" | jq -c '{iss,sub,aud,ttl:(.exp-.iat)}')"

  section "the OSB broker provisions '$OSB_SA_SERVICE' (jwt by default)"
  osb_register_tenant
  k apply -f "$LOCAL_DIR/manifests/osb-stub.yaml" >/dev/null
  wait_rollout deploy/echo osb-stub 120s >/dev/null
  sip="$(k -n osb-stub get svc echo -o jsonpath='{.spec.clusterIP}')"
  [ -n "$sip" ] || die "PHASE36: osb-stub echo ClusterIP unresolved"
  r="$(osb_call DELETE "/v1/services/$OSB_SA_SERVICE")"
  if [ "${r%% *}" = 202 ]; then osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"; fi
  r="$(osb_call POST /v1/services \
    "{\"name\":\"$OSB_SA_SERVICE\",\"team\":\"$OSB_TEAM\",\"host\":\"$sip\",\"port\":5678,\"protocol\":\"HTTP\"}")"
  [ "${r%% *}" = 202 ] || die "PHASE36 FAIL: provision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  node="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].spec.nodeName}')"
  gwip="$(k get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  [ -n "$gwip" ] || die "PHASE36: no edge-proxy node IP"

  section "GREEN — agent-sa -> $sip through the gateway ($node, $gwip:80) with its $aud token: 200"
  i=0
  while :; do
    out="$(sa_agent_curl gateway "$sip" "$gwip")"
    [ "${out##*$'\n'}" = 200 ] && has "$out" OSB-PROVISIONED-BACKEND && break
    i=$((i + 1))
    [ "$i" -lt 30 ] || { printf '%s\n' "$out" | tail -5; die "PHASE36 FAIL: agent-sa's own ServiceAccount token never got through the gateway (last: HTTP ${out##*$'\n'})"; }
    sleep 2
  done
  ok "HTTP 200 $(printf '%s\n' "$out" | head -1) — served on the agent's own ServiceAccount token"

  section "RED — the same agent's token for billing.internal: 401"
  out="$(sa_agent_curl other "$sip" "$gwip")"
  [ "${out##*$'\n'}" = 401 ] && ! has "$out" OSB-PROVISIONED-BACKEND \
    || die "PHASE36 FAIL: agent-sa's token for billing.internal got HTTP ${out##*$'\n'}, want 401"
  ok "HTTP 401 — a token projected for an audience the gateway does not list is refused"

  section "deprovision '$OSB_SA_SERVICE', remove $SA_AGENT_NS"
  r="$(osb_call DELETE "/v1/services/$OSB_SA_SERVICE")"
  [ "${r%% *}" = 202 ] || die "PHASE36: deprovision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  k delete namespace "$SA_AGENT_NS" --ignore-not-found --wait=false >/dev/null
  ok "PHASE 36 — an agent's ServiceAccount token projected for $aud got 200 from an OSB service through the gateway, its token for billing.internal 401, and auth-service fetched the API server's keys with its own token, the keys closed to anonymous callers"
}

main() {
  phase1_cluster
  verify_phase1
  phase2_deps
  verify_phase2
  phase3_images
  verify_phase3
  phase4_dataplane_pki
  verify_phase4
  phase5_secrets
  verify_phase5
  phase6_migrate
  verify_phase6
  phase7_deploy
  verify_phase7
  phase8_seed
  verify_phase8
  phase9_prove
  phase25_default_jwt_osb   # the defaults alone, before phase 12 flips anything
  phase10_sec3_admission
  phase26_signed_images
  phase11_sec3_dataplane
  phase12_extauthz_cutover
  phase13_inconsistent_guard
  phase14_failstatic_metrics
  phase15_osb_broker
  phase16_sds_scope
  phase17_network_policy
  phase18_scim_oidc
  phase19_confidential
  phase20_sni_certs
  phase21_osb_https_public_host
  phase22_listener_collision
  phase23_connection_manager
  phase24_telemetry
  phase27_agent_svids
  phase28_egress_gateway
  phase29_egress_lockdown
  phase30_keyless_agents
  phase31_agent_rate_limits
  phase34_helm_test         # before 32: the test pods pull their image
  phase32_no_internet
  phase33_kek_rotation
  phase36_sa_token_gateway
  phase35_licence
  section "up.sh: FULL STANDUP COMPLETE — routable + SEC-3 + ext_authz LIVE + R8 fail-static inconsistent guard + fail-static metrics + OSB broker + per-node SDS + chart NetworkPolicies + SCIM/OIDC sign-in + attested confidential workload + per-route SNI certs + OSB HTTPS public host over a DNS upstream + a colliding :443 gateway refused + forged identity headers stripped and a path traversal refused + every listener's access log and trace in the OTel collector + an unsigned image refused at admission + an agent pod without an SVID refused at the TLS handshake + an agent reaching a TLS provider only through edge-egress + agent namespaces locked to edge-egress by Kyverno + a key planted in a keyless agent never reaching the provider + a burst from one agent refused with 429 while another is served, in a decision log whose exported hash chain verifies + the whole stack restarted and serving with no internet, and not one DNS query for a name outside the cluster + the secrets KEK rotated with every key re-sealed and the same cert still served over SDS + every release passing its own helm test + an agent's own ServiceAccount token served through the gateway and its token for another audience refused + an expired licence warned about with edge_licence_valid 0 and both tenants still served."
}

# Entry: no args -> full standup; args -> run the named phase function(s) in order
# (e.g. `up.sh phase4_dataplane_pki verify_phase4` to re-run just Phase 4).
if [ "$#" -gt 0 ]; then
  for _fn in "$@"; do "$_fn"; done
else
  main
fi
