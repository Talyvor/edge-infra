#!/usr/bin/env bash
# cutover.sh — the CFG-1 launch-day cutover (ext_authz ON), rehearsed IN ORDER on
# a throwaway kind cluster, with a check after every step. The real-cluster
# version of the same steps is docs/ext-authz-launch-runbook.md.
#
#   make kind-cutover                   # == deploy/local/cutover.sh
#   KEEP_CLUSTER=1 make kind-cutover    # leave the cluster up afterwards
#   deploy/local/cutover.sh step4_enable  # re-run named step(s) on a kept cluster
#
# The order, and why it is this order (each reason is checked below):
#   0  main as committed — the control-plane image pin (values.yaml) predates
#      /readyz and xDS TLS, so under main's charts it never turns Ready and Envoy
#      cannot reach it: nothing is served. The bump is not optional.
#   1  image bump, ext_authz still OFF — xDS becomes mandatory mTLS and the CFG-1
#      guard (internal/xds/reconciler.go, "refusing to build snapshot") goes
#      live. A control shows that ONE auth_policy='jwt' route arriving in this
#      window freezes the whole fleet on last-good — so provisioning (OSB, whose
#      default auth_policy is jwt) stays frozen until step 4.
#   2  auth-service with JWKS and mTLS — fetches the issuer's JWKS before it
#      listens, and refuses a TLS client that presents no certificate.
#   3  client certificate — envoy-authz-client-cert issued, mounted on every
#      edge-proxy, and accepted by the auth-service.
#   4  enable — ext_authz ON; then the first jwt route is provisioned and gated.
#
# After every step: tenant routes (auth_policy=none) answer 200, a jwt route is
# never served without a valid token, and the fleet is not frozen — a brand-new
# route is published, acked by EVERY edge-proxy and served. Steps 2-4 also run a
# prober for the whole step and fail on any refused tenant request.
#
# Uses its own cluster name (edge-cutover) and refuses to start if it exists, so
# the teardown only ever deletes a cluster this run created.
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-cutover}"
# Source up.sh for its phase functions and helpers without running a phase (its
# entry point runs each argument as a function; `:` is a no-op).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/up.sh" :

require_toolchain docker kind kubectl helm jq openssl curl git

# The committed image pin — the image a sync of main would deploy today.
PIN="$(sed -n 's/^  tag: "\([0-9a-f]\{40\}\)".*/\1/p' "$REPO_ROOT/deploy/helm/edge-control-plane/values.yaml" | head -1)"
[ -n "$PIN" ] || die "could not read the control-plane image pin from values.yaml"
PIN_TAG="pin-${PIN:0:7}"
# The pin's own Dockerfile hard-codes GOARCH=amd64; build its source with the same
# Go base image main's Dockerfile uses, for whatever arch the kind nodes are.
PIN_GO_IMAGE="${PIN_GO_IMAGE:-golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c}"

# The admin READ API is off in every overlay; the cutover turns it on so each
# check can ask the control plane what it is actually running.
ADMIN_SECRET=edge-cp-admin
ADMIN_KEY=local-cutover-admin-key
ADMIN_LP="${ADMIN_LP:-18402}"
METRICS_LP="${METRICS_LP:-12412}"
STATE="$LOCAL_DIR/.cutover-state"   # counter baseline carried between steps

# ---- helm releases, always rendered from scratch ------------------------------
# --reset-values on every upgrade: Helm carries earlier --set values forward
# otherwise, and a step must deploy exactly what it says.
cp_release() {  # <image-tag> <extAuthz.enabled> [extra helm args...]
  local tag="$1" ea="$2"; shift 2
  h upgrade --install edge-control-plane "$REPO_ROOT/deploy/helm/edge-control-plane" -n "$INFRA_NS" \
    --reset-values \
    -f "$LOCAL_DIR/values/values-control-plane.yaml" \
    --set image.tag="$tag" \
    --set adminApi.existingSecret="$ADMIN_SECRET" \
    --set extAuthz.enabled="$ea" "$@"
}
proxy_release() {  # <extAuthz.clientTLS.enabled>
  h upgrade --install edge-proxy "$REPO_ROOT/deploy/helm/edge-proxy" -n edge --create-namespace \
    --reset-values \
    --set extAuthz.clientTLS.enabled="$1" --wait --timeout 300s
}

# ---- reading the control plane -------------------------------------------------
cp_pod() {  # the Ready, non-terminating control-plane pod (empty if none)
  k -n "$INFRA_NS" get pod -l app.kubernetes.io/name=edge-control-plane -o json \
    | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)
              | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))][0].metadata.name // empty'
}
pf_get() {  # <pod-port> <local-port> <path> [curl args...] — GET through a port-forward to cp_pod
  local port="$1" lp="$2" path="$3" pod out="" pf i=0; shift 3
  pod="$(cp_pod)"; [ -n "$pod" ] || return 0
  k -n "$INFRA_NS" port-forward "pod/$pod" "$lp:$port" >/dev/null 2>&1 &
  pf=$!
  while [ "$i" -lt 15 ]; do
    out="$(curl -s --max-time 4 "$@" "http://127.0.0.1:$lp$path" 2>/dev/null || true)"
    [ -n "$out" ] && break
    i=$((i + 1)); sleep 1
  done
  kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  printf '%s' "$out"
}
admin_get() { pf_get 18002 "$ADMIN_LP" "$1" -H "X-Admin-Key: $ADMIN_KEY"; }
auth_off_blocked() {  # xds_snapshots_blocked_total{reason="auth_wanted_extauthz_off"} on the live process
  local v; v="$(blocked_of "$(pf_get 2112 "$METRICS_LP" /metrics)" auth_wanted_extauthz_off)"
  [ -n "$v" ] || die "could not read xds_snapshots_blocked_total{reason=\"auth_wanted_extauthz_off\"}"
  printf '%s' "$v"
}

# ---- the checks run after every step -------------------------------------------
# canary <add|drop> <host> — a none-route to tenant-a's backend, written straight
# to Postgres as any provisioner would.
canary() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  if [ "$1" = add ]; then
    k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -c \
      "INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy)
       VALUES ('$2','$2','local-gw',ARRAY['$2']::text[],'/','tenant-a',30,'none')
       ON CONFLICT (name) DO UPDATE SET deleted_at=NULL, updated_at=now();" >/dev/null
  else
    k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -c \
      "DELETE FROM routes WHERE name='$2';" >/dev/null
  fi
}
served_within() {  # <host> <expected-code> <tries> — poll the gateway every 2s
  local i=0
  while [ "$i" -lt "$3" ]; do [ "$(gw_code "$1")" = "$2" ] && return 0; i=$((i + 1)); sleep 2; done
  return 1
}
# fleet_live <label> — NOT frozen on last-good: a route written now is published,
# acked by every connected edge-proxy (one stream per proxy pod, none behind) and
# served; removing it is published too. The ack wait is 90s: after the
# control-plane pod moves node, each proxy reconnects on Envoy's xDS retry
# backoff, which grows to about 30s (the chart sets no retry policy).
fleet_live() {
  local host="canary-$1.local" nodes="" want got="" i=0
  canary add "$host"
  served_within "$host" 200 20 || { canary drop "$host"; die "FROZEN after $1: a new route was not served within 40s"; }
  want="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o json \
    | jq '[.items[] | select(.metadata.deletionTimestamp == null)
           | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length')"
  while [ "$i" -lt 45 ]; do
    nodes="$(admin_get /admin/v1/nodes)"
    got="$(printf '%s' "$nodes" | jq -r '.published_version as $v
      | "\(.active_streams) \(.nodes_behind) \([.nodes[] | select(.acked_version != $v)] | length)"' 2>/dev/null || true)"
    [ "$got" = "$want 0 0" ] && break
    i=$((i + 1)); sleep 2
  done
  [ "$got" = "$want 0 0" ] || { canary drop "$host"; die "FROZEN after $1: streams/behind/unacked = $got, want $want 0 0 — $nodes"; }
  canary drop "$host"
  served_within "$host" 404 20 || die "FROZEN after $1: removing a route was not published within 40s"
  ok "fleet live after $1 — a new route was published, acked by all $want edge-proxies, served, and removed"
}
tenants_200() {  # <label>
  local a b; a="$(gw_code tenant-a.local)"; b="$(gw_code tenant-b.local)"
  [ "$a" = 200 ] && [ "$b" = 200 ] || die "ALLOWED REQUEST REFUSED after $1: tenant-a=$a tenant-b=$b (want 200)"
  ok "tenant-a.local / tenant-b.local (auth_policy=none, no token) -> 200 / 200"
}
expect_auth_off_blocked() {  # <label> <want> — the CFG-1 guard has refused exactly <want> snapshots
  local v; v="$(auth_off_blocked)"
  [ "$v" = "$2" ] || die "after $1: xds_snapshots_blocked_total{reason=\"auth_wanted_extauthz_off\"}=$v, want $2"
  ok "CFG-1 guard refusals on this control-plane process: $v (want $2)"
}

# prober_start / prober_stop <label> [tolerate-unanswered] — hit both tenants
# every 0.3s for the length of a step. A refused request (any answer but 200)
# fails the step. A request that got no answer at all (000) fails it too, unless
# the step restarts the edge-proxy pods themselves: kind publishes :443 from ONE
# node with no load balancer in front to drain to, so that pod's restart drops
# its connections for a moment. That count is printed, not hidden.
PROBER_PID=""
prober_start() {
  : > "$LOCAL_DIR/.cutover-probe"
  ( while true; do printf '%s %s\n' "$(gw_code tenant-a.local)" "$(gw_code tenant-b.local)"; sleep 0.3; done ) \
    >> "$LOCAL_DIR/.cutover-probe" 2>/dev/null &
  PROBER_PID=$!
}
prober_stop() {
  kill "$PROBER_PID" >/dev/null 2>&1 || true; wait "$PROBER_PID" 2>/dev/null || true; PROBER_PID=""
  local f="$LOCAL_DIR/.cutover-probe" total refused unanswered
  total="$(wc -l < "$f" | tr -d ' ')"
  refused="$(tr ' ' '\n' < "$f" | grep -cvE '^(200|000)$' || true)"
  unanswered="$(tr ' ' '\n' < "$f" | grep -cx '000' || true)"
  echo "  prober during $1: $total rounds x 2 tenants — refused=$refused unanswered=$unanswered"
  [ "$total" -gt 0 ] || die "prober during $1 recorded nothing"
  [ "$refused" = 0 ] || die "ALLOWED REQUEST REFUSED during $1: $(tr ' ' '\n' < "$f" | grep -vE '^(200|000)$' | sort | uniq -c | tr '\n' ' ')"
  if [ "${2:-}" = tolerate-unanswered ]; then
    [ "$unanswered" = 0 ] || warn "$unanswered requests unanswered while the :443 edge-proxy pod restarted (kind has no LB to drain to)"
  else
    [ "$unanswered" = 0 ] || die "ALLOWED REQUEST DROPPED during $1: $unanswered requests got no answer"
  fi
  ok "no tenant request refused during $1"
}

# authz_probe <with-cert|no-cert> — a TLS client to the auth-service gRPC port
# from the edge namespace; echoes "code=<http> exit=<curl exit>". with-cert
# presents envoy-authz-client-tls-secret and verifies the server against its CA.
# The pod runs detached and its result is read from its log once it has finished:
# `kubectl run --rm -i` lost the output whenever the container exited before
# kubectl attached, and that empty string then read as a refusal.
authz_probe() {
  local name="authz-probe-$1" url="https://auth-service.${INFRA_NS}.svc.cluster.local:50051/" cmd spec phase log out
  if [ "$1" = with-cert ]; then
    cmd="curl -s --max-time 6 --cacert /c/ca.crt --cert /c/tls.crt --key /c/tls.key -o /dev/null -w code=%{http_code} $url; echo \" exit=\$?\""
  else
    cmd="curl -sk --max-time 6 -o /dev/null -w code=%{http_code} $url; echo \" exit=\$?\""
  fi
  spec="$(jq -cn --arg n "$name" --arg img "$ATTACKER_IMAGE" --arg cmd "$cmd" --arg mode "$1" '
    {spec: ({containers: [({name: $n, image: $img, command: ["sh", "-c", $cmd]}
              + (if $mode == "with-cert" then {volumeMounts: [{name: "c", mountPath: "/c", readOnly: true}]} else {} end))]}
            + (if $mode == "with-cert" then {volumes: [{name: "c", secret: {secretName: "envoy-authz-client-tls-secret"}}]} else {} end))}')"
  k -n edge delete pod "$name" --ignore-not-found >/dev/null 2>&1 || true
  k -n edge run "$name" --restart=Never --image="$ATTACKER_IMAGE" --overrides="$spec" >/dev/null
  # The command ends in `echo`, so a probe that ran exits 0 whatever curl got.
  k -n edge wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$name" --timeout=120s >/dev/null 2>&1 || true
  phase="$(k -n edge get pod "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  log="$(k -n edge logs "$name" 2>/dev/null || true)"
  k -n edge delete pod "$name" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  [ "$phase" = Succeeded ] || die "authz probe pod $name did not finish within 120s (phase=${phase:-unknown}): ${log}"
  out="$(printf '%s' "$log" | grep -o 'code=[0-9]* exit=[0-9]*' | tail -1 || true)"
  [ -n "$out" ] || die "authz probe produced no output (pod $name finished, log: '${log}')"
  printf '%s\n' "$out"
}

# ---- setup: the cluster and everything that is not part of the cutover ----------
setup() {
  section "SETUP — cluster, deps, images, PKI, secrets, schema (up.sh phases 1-6)"
  phase1_cluster; verify_phase1
  phase2_deps; verify_phase2
  phase3_images; verify_phase3
  phase4_dataplane_pki; verify_phase4
  phase5_secrets; verify_phase5
  phase6_migrate; verify_phase6

  section "build the committed control-plane pin ($PIN) from its own source"
  local src; src="$(mktemp -d)"
  git -C "$REPO_ROOT" archive "$PIN" | tar -x -C "$src"
  cat > "$src/Dockerfile.cutover-pin" <<'EOF'
ARG GO_IMAGE
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s" -o /bin/server ./cmd/server
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /bin/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
EOF
  docker build --build-arg GO_IMAGE="$PIN_GO_IMAGE" -f "$src/Dockerfile.cutover-pin" \
    -t "edge-control-plane:$PIN_TAG" "$src"
  rm -rf "$src"
  kind load docker-image --name "$CLUSTER_NAME" "edge-control-plane:$PIN_TAG"

  # The edge-proxy chart issues the authz client cert only while
  # extAuthz.clientTLS.enabled, which is step 3 — so it does not exist before then
  # (these deletes matter only on a re-run over a cluster that got that far).
  section "withhold the ext_authz client cert until step 3"
  k -n edge delete certificate envoy-authz-client-cert --ignore-not-found
  k -n edge delete secret envoy-authz-client-tls-secret --ignore-not-found
  apply_secret "$INFRA_NS" generic "$ADMIN_SECRET" --from-literal=admin-api-key="$ADMIN_KEY" >/dev/null
  ok "setup done — no control-plane, no auth-service, no authz client cert yet"
}

# ---- step 0: main as committed ---------------------------------------------------
step0_committed() {
  section "STEP 0 — main as committed: control-plane at the pin ($PIN_TAG), ext_authz OFF"
  # No --wait: whether it ever turns Ready is what this step measures.
  cp_release "$PIN_TAG" false
  helm_install edge-issuer "$INFRA_NS" || diag_fail edge-issuer "$INFRA_NS"
  # The proxy chart REQUIRES the authz client cert volume; it does not exist until
  # step 3, so the proxy starts without the mount and is re-rolled with it there.
  proxy_release false
  phase8_seed

  section "CHECK 0 — the pin never turns Ready, and the gateway serves nothing"
  sleep 45
  local img ready ev code
  img="$(k -n "$INFRA_NS" get deploy edge-control-plane -o jsonpath='{.spec.template.spec.containers[0].image}')"
  [ "$img" = "edge-control-plane:$PIN_TAG" ] || die "control-plane image is $img, want edge-control-plane:$PIN_TAG"
  ready="$(k -n "$INFRA_NS" get deploy edge-control-plane -o jsonpath='{.status.readyReplicas}')"
  [ "${ready:-0}" = 0 ] || die "the pin turned Ready ($ready) — the premise of this rehearsal is wrong; re-derive the order"
  ev="$(k -n "$INFRA_NS" get events --field-selector reason=Unhealthy -o jsonpath='{.items[*].message}')"
  has "$ev" ":18001/readyz" || die "expected the pin's readiness probe to fail on :18001/readyz; events: $ev"
  ok "control-plane $img: 0 Ready — readiness fails on :18001/readyz, which the pin does not serve"
  code="$(gw_code tenant-a.local)"
  [ "$code" != 200 ] || die "tenant-a served 200 at the pin — expected nothing to be served"
  ok "gateway serves nothing at the pin (tenant-a.local -> $code): the bump is step 1, not an option"
}

# ---- step 1: image bump ----------------------------------------------------------
step1_image_bump() {
  section "STEP 1 — image bump: control-plane -> :$IMAGE_TAG, ext_authz still OFF"
  cp_release "$IMAGE_TAG" false --wait --timeout 240s

  section "CHECK 1 — the bumped binary is running, reads its flags, and serves"
  local cfg
  cfg="$(admin_get /admin/v1/config)"
  [ "$(printf '%s' "$cfg" | jq -c '[.xds.tls, .xds.client_ca, .ext_authz.enabled]')" = '[true,true,false]' ] \
    || die "admin config is not {xds mTLS on, ext_authz off}: $cfg"
  ok "admin /config: xds.tls=true xds.client_ca=true (mandatory mTLS) ext_authz.enabled=false"
  served_within tenant-a.local 200 20 || die "tenant-a not served after the bump"
  tenants_200 "step 1"
  expect_auth_off_blocked "step 1" 0
  fleet_live s1

  # CONTROL — what a jwt route does in this window, i.e. why provisioning stays
  # frozen until step 4, and proof that fleet_live can see a freeze.
  section "CONTROL 1 — one auth_policy='jwt' route while ext_authz is OFF freezes the fleet"
  k apply -f "$LOCAL_DIR/manifests/secure-backend.yaml" >/dev/null
  wait_rollout deploy/whoami tenant-secure 120s >/dev/null
  local wip; wip="$(k -n tenant-secure get svc whoami -o jsonpath='{.spec.clusterIP}')"
  seed_secure_route "$wip"
  canary add canary-frozen.local
  sleep 20
  local frozen; frozen="$(gw_code canary-frozen.local)"
  local blocked; blocked="$(auth_off_blocked)"
  [ "$frozen" != 200 ] || die "CONTROL FAIL: the canary was served — the guard did not freeze publishing"
  [ "$blocked" -gt 0 ] || die "CONTROL FAIL: the CFG-1 guard counter did not rise ($blocked)"
  [ "$(gw_code secure.local)" != 200 ] || die "CONTROL FAIL: secure.local (jwt) served while ext_authz OFF"
  tenants_200 "control 1 (last-good keeps serving)"
  ok "FROZEN as predicted: guard refused $blocked snapshot(s); a new route waited ($frozen); jwt route not served"
  drop_secure_route
  canary drop canary-frozen.local
  served_within tenant-a.local 200 10 >/dev/null || true
  fleet_live s1-thawed
  auth_off_blocked > "$STATE"
  ok "STEP 1 done — and provisioning must stay frozen until step 4"
}

# ---- step 2: auth-service with JWKS and mTLS -------------------------------------
step2_auth_service() {
  section "STEP 2 — auth-service :$IMAGE_TAG with JWKS (issuer) and mTLS (client CA)"
  prober_start
  helm_install auth-service "$INFRA_NS" || { prober_stop "step 2"; diag_fail auth-service "$INFRA_NS"; }
  sleep 3
  prober_stop "step 2"

  section "CHECK 2 — JWKS fetched before listening; mTLS refuses a client with no cert"
  local logs probe
  logs="$(k -n "$INFRA_NS" logs deploy/auth-service --tail=50)"
  has "$logs" '"mtls":true' || die "auth-service did not start with mTLS: $logs"
  has "$logs" 'grpc server listening' || die "auth-service is not listening (JWKS fetch failed?): $logs"
  ok "auth-service started tls=true mtls=true and listens — it fetches the JWKS before it listens, and exits if it cannot"
  probe="$(authz_probe no-cert)"
  case "$probe" in "code=000 exit="[1-9]*) ;; *) die "a client with NO cert was not refused by the auth-service: $probe" ;; esac
  ok "TLS client without a certificate -> refused ($probe)"
  tenants_200 "step 2"
  expect_auth_off_blocked "step 2" "$(cat "$STATE")"
  fleet_live s2
}

# ---- step 3: client certificate --------------------------------------------------
step3_client_cert() {
  section "STEP 3 — client certificate: the edge-proxy chart issues envoy-authz-client-cert and mounts it on every edge-proxy"
  prober_start
  proxy_release true
  k -n edge wait --for=condition=Ready certificate/envoy-authz-client-cert --timeout=120s
  k -n edge rollout status ds/edge-proxy --timeout=180s
  sleep 3
  prober_stop "step 3" tolerate-unanswered

  section "CHECK 3 — mounted on every edge-proxy, and the auth-service accepts it"
  local p n=0 probe
  for p in $(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o name); do
    k -n edge exec "$p" -c envoy -- ls /etc/authz-client-tls/ca.crt /etc/authz-client-tls/tls.crt /etc/authz-client-tls/tls.key >/dev/null \
      || die "$p lacks the authz client cert at /etc/authz-client-tls — the flip would render plaintext => deny-all"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || die "no edge-proxy pods"
  ok "all $n edge-proxy pods mount /etc/authz-client-tls/{ca.crt,tls.crt,tls.key}"
  probe="$(authz_probe with-cert)"
  case "$probe" in "code=000"*|*"exit="[1-9]*|"") die "the auth-service did not accept the client cert: '$probe'" ;; esac
  ok "TLS client WITH envoy-authz-client-tls-secret -> handshake accepted, server verified against its CA ($probe)"
  tenants_200 "step 3"
  expect_auth_off_blocked "step 3" "$(cat "$STATE")"
  fleet_live s3
}

# ---- step 4: enable ----------------------------------------------------------------
step4_enable() {
  section "STEP 4 — enable: ext_authz ON (same image)"
  prober_start
  cp_release "$IMAGE_TAG" true --wait --timeout 240s
  sleep 10
  prober_stop "step 4"

  section "CHECK 4 — the control-plane reports ext_authz on, nothing frozen, tenants untouched"
  local cfg
  cfg="$(admin_get /admin/v1/config)"
  [ "$(printf '%s' "$cfg" | jq -c '[.ext_authz.enabled, .ext_authz.tls, .ext_authz.mtls]')" = '[true,true,true]' ] \
    || die "admin config does not report ext_authz enabled with mTLS: $cfg"
  ok "admin /config: ext_authz enabled=true tls=true mtls=true"
  tenants_200 "step 4"
  expect_auth_off_blocked "step 4" 0
  fleet_live s4

  section "CHECK 4b — provisioning unfrozen: the first jwt route is published GATED"
  k apply -f "$LOCAL_DIR/manifests/secure-backend.yaml" >/dev/null
  wait_rollout deploy/whoami tenant-secure 120s >/dev/null
  seed_secure_route "$(k -n tenant-secure get svc whoami -o jsonpath='{.spec.clusterIP}')"
  served_within secure.local 401 20 || die "secure.local not published gated (no token should be 401, got $(gw_code secure.local))"
  ok "secure.local (jwt) published — no token -> 401"

  local UMAIL="cutover@edge.local" UPASS="cutover-password-12345" TOK="" i=0
  k -n "$INFRA_NS" exec deploy/edge-issuer -- /issuer adduser --email "$UMAIL" --password "$UPASS" --team eng >/dev/null 2>&1 || true
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=120s >/dev/null
  while [ "$i" -lt 10 ]; do
    TOK="$(k -n tenant-secure exec minter -- curl -sk --max-time 6 -X POST \
      "https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081/login" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$UMAIL\",\"password\":\"$UPASS\"}" 2>/dev/null | jq -r '.access_token // empty' 2>/dev/null || true)"
    [ -n "$TOK" ] && break
    i=$((i + 1)); sleep 2
  done
  [ -n "$TOK" ] || die "could not mint a JWT from the issuer"

  section "CHECK 4c — every request class, 10 rounds: allowed -> 200, refused -> 401, never crossed"
  local r a b none garbage valid body
  for r in $(seq 1 10); do
    a="$(gw_code tenant-a.local)"; b="$(gw_code tenant-b.local)"
    none="$(gw_code secure.local)"; garbage="$(gw_code secure.local -H 'Authorization: Bearer not-a-jwt')"
    valid="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
    [ "$a $b $valid" = "200 200 200" ] || die "ALLOWED REQUEST REFUSED (round $r): tenant-a=$a tenant-b=$b secure+valid-JWT=$valid"
    [ "$none $garbage" = "401 401" ] || die "REFUSED REQUEST NOT REFUSED (round $r): secure no-token=$none garbage=$garbage (want 401 401)"
  done
  ok "10/10 rounds: tenants 200, secure.local + valid JWT 200, no token 401, garbage token 401"
  body="$(gw_body secure.local -H "Authorization: Bearer $TOK" -H 'x-user-email: attacker@evil.com' | tr 'A-Z' 'a-z')"
  has "$body" "x-user-email: $UMAIL" || die "the backend did not receive the JWT's identity header: $body"
  has "$body" 'attacker@evil.com' && die "a client-forged x-user-email reached the backend"
  ok "the backend sees x-user-email: $UMAIL from the token; the forged one is overwritten"
  expect_auth_off_blocked "step 4 (jwt route present)" 0
  fleet_live s4-jwt
  ok "CUTOVER DONE — ext_authz on, no allowed request refused, no refused request allowed, fleet never frozen"
}

rehearse() {
  setup
  step0_committed
  step1_image_bump
  step2_auth_service
  step3_client_cert
  step4_enable
}

if [ "$#" -gt 0 ]; then
  for _fn in "$@"; do "$_fn"; done
  # `return` when sourced (rollback.sh sources this with `:` for its steps).
  return 0 2>/dev/null || exit 0
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (CLUSTER_NAME=$CLUSTER_NAME deploy/local/down.sh) or pick another CLUSTER_NAME"
fi
started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  [ -n "$PROBER_PID" ] && kill "$PROBER_PID" >/dev/null 2>&1 || true
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "cutover FAILED (exit $rc) — cluster state before teardown"
    k get pods -A -o wide 2>/dev/null || true
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up; delete it with: CLUSTER_NAME=$CLUSTER_NAME deploy/local/down.sh"
  else
    bash "$LOCAL_DIR/down.sh" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
  fi
  rm -f "$STATE" "$LOCAL_DIR/.cutover-probe"
  if [ "$rc" = 0 ]; then
    ok "kind-cutover PASSED in $(( ($(date +%s) - started) / 60 )) min — steps 0-4 checked in order, cluster removed"
  else
    printf '%s  X kind-cutover FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT
rehearse
