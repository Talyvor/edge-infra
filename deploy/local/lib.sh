#!/usr/bin/env bash
# lib.sh — shared config + helpers for the edge-infra LOCAL standup tooling.
#
# Sourced by up.sh / down.sh (and phase helpers). Sourcing has no side effects
# beyond defining variables and functions. Every knob is overridable via env so
# the standup is reproducible AND tweakable without editing tracked files.

# ---- repo layout (this file lives at <repo>/deploy/local/lib.sh) -------------
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LOCAL_DIR/../.." && pwd)"

# ---- knobs -------------------------------------------------------------------
CLUSTER_NAME="${CLUSTER_NAME:-edge-local}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
INFRA_NS="${INFRA_NS:-infra}"                 # all edge-infra services live here
IMAGE_TAG="${IMAGE_TAG:-local}"               # local image tag the charts point at
IMAGE_SOURCE="${IMAGE_SOURCE:-build}"         # build | registry (the release-pinned images; up.sh Phase 3)

# Pinned dependency versions (fetched at run time, like any kind bootstrap).
# up.sh fails loudly if a URL is unreachable rather than standing up half a stack.
# Pinned for k8s 1.35 (kind 0.31 default node image) — newest that supports it.
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-}"        # empty => kind's default for this kind binary
CALICO_VERSION="${CALICO_VERSION:-v3.30.2}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.20.0}"
KYVERNO_VERSION="${KYVERNO_VERSION:-v1.16.0}"
CSI_DRIVER_SPIFFE_VERSION="${CSI_DRIVER_SPIFFE_VERSION:-v0.15.0}"   # jetstack chart; issues agent SVIDs (Phase 27)

# In-cluster dev datastores (Phase 2) are dev-grade (ephemeral emptyDir, single
# replica). Their images are pinned in deploy/local/manifests/{postgres,nats}.yaml.

# Public images the stack pulls (pinned to the chart defaults). Loaded into the
# cluster in Phase 3 to avoid docker-hub pull limits at pod-creation time.
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.39.2@sha256:460f8c329f24b2e1c7c5af64cb314a6f351ad1c262ba77b135ac46b35ebd5f85}"
BUSYBOX_IMAGE="${BUSYBOX_IMAGE:-busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
# The charts' `helm test` image (tests.image in each chart's values.yaml).
TEST_IMAGE="${TEST_IMAGE:-curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69}"
# Trivial echo backend for the two tenants (Phase 8). Kept in sync with
# deploy/local/manifests/tenants.yaml.
ECHO_IMAGE="${ECHO_IMAGE:-hashicorp/http-echo:0.2.3}"
# Attacker pod for the SEC-3 data-plane proof (Phase 11): a pod-network pod (NOT
# hostNetwork) with curl, so its source IP is a POD IP outside NODE_CIDR.
ATTACKER_IMAGE="${ATTACKER_IMAGE:-curlimages/curl:8.11.1}"
# Header-reflecting backend for the ext_authz proof (Phase 12): whoami echoes the
# request headers so the auth-service's injected identity headers are visible.
WHOAMI_IMAGE="${WHOAMI_IMAGE:-traefik/whoami:v1.10.4}"
DEX_IMAGE="${DEX_IMAGE:-ghcr.io/dexidp/dex:v2.41.1}"
# Signed-image admission (Phase 26): one pair per signer generation, each from a
# main images.yaml run. *SIGNED_IMAGE is a multi-arch image that run signed;
# *UNSIGNED_IMAGE is the per-arch auth-service intermediate it merged into the
# signed index, which nothing signs.
# Built under the Talyvor organisation (fe80ad1): ghcr.io/talyvor, signed by Talyvor/edge-infra.
SIGNED_IMAGE="${SIGNED_IMAGE:-ghcr.io/talyvor/edge-osb:fe80ad1d40d2eb2a624ae2a128a780ec640654ee}"
UNSIGNED_IMAGE="${UNSIGNED_IMAGE:-ghcr.io/talyvor/auth-service:fe80ad1d40d2eb2a624ae2a128a780ec640654ee-amd64}"
# Built before 12 Oct 2026, when this repository moved from gaboracnicolai to the Talyvor
# organisation (608373a): ghcr.io/gaboracnicolai, signed by gaboracnicolai/edge-infra, which
# the policy's before-the-move rule checks. Drop this pair when that rule goes.
OLD_SIGNED_IMAGE="${OLD_SIGNED_IMAGE:-ghcr.io/gaboracnicolai/edge-osb:608373ac9acc3dafc036da69cb2ef7251182db6d}"
OLD_UNSIGNED_IMAGE="${OLD_UNSIGNED_IMAGE:-ghcr.io/gaboracnicolai/auth-service:608373ac9acc3dafc036da69cb2ef7251182db6d-amd64}"

# SCIM bearer token the local issuer accepts (Phase 5 secret, Phase 18 client).
SCIM_TOKEN="local-dev-scim-token-0123456789abcdef"

# ---- logging -----------------------------------------------------------------
if [ -t 1 ]; then
  C_BLUE=$'\033[1;34m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
  C_RED=$'\033[1;31m';  C_DIM=$'\033[2m';    C_RST=$'\033[0m'
else
  C_BLUE=; C_GRN=; C_YEL=; C_RED=; C_DIM=; C_RST=
fi
section() { printf '\n%s==> %s%s\n' "$C_BLUE" "$*" "$C_RST"; }
log()  { printf '%s  - %s%s\n' "$C_DIM" "$*" "$C_RST"; }
ok()   { printf '%s  OK %s%s\n' "$C_GRN" "$*" "$C_RST"; }
warn() { printf '%s  ! %s%s\n'  "$C_YEL" "$*" "$C_RST" >&2; }
die()  { printf '%s  X %s%s\n'   "$C_RED" "$*" "$C_RST" >&2; exit 1; }

# ---- guards ------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"; }
require_toolchain() { local t; for t in "$@"; do need "$t"; done; }

# kubectl/helm pinned to OUR context — never touches the operator's other
# kube-contexts even though `kind create` flips current-context.
k() { kubectl --context "$KUBE_CONTEXT" "$@"; }
h() { helm --kube-context "$KUBE_CONTEXT" "$@"; }

# ---- waiters -----------------------------------------------------------------
# retry <tries> <sleep-seconds> <cmd...>
retry() { local n="$1" s="$2"; shift 2; local i; for ((i=1; i<=n; i++)); do "$@" && return 0; sleep "$s"; done; return 1; }

# gw_code <host> [extra curl args...] — HTTP status of a request through the node
# :443 for the given Host. gw_body returns the response body. (Empty "$@" is safe
# under set -u — only *named* arrays trip it, not the positional list.)
gw_code() { local host="$1"; shift; curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H "Host: $host" "$@" http://127.0.0.1:443/ 2>/dev/null || true; }
gw_body() { local host="$1"; shift; curl -s --max-time 6 -H "Host: $host" "$@" http://127.0.0.1:443/ 2>/dev/null || true; }

# has <haystack> <needle> — substring test with NO pipe. Deliberately avoids
# `printf "$big" | grep -q`: with `set -o pipefail`, grep -q exits on first match
# and SIGPIPEs the still-writing printf (exit 141), so the pipeline reports
# failure DESPITE a match when the input exceeds the pipe buffer (~64 KiB).
has() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

# b64url_d <base64url> — decode unpadded base64url (a JWS segment) to stdout.
b64url_d() {
  local s; s="$(printf '%s' "$1" | tr '_-' '/+')"
  while [ $(( ${#s} % 4 )) -ne 0 ]; do s="$s="; done
  printf '%s' "$s" | openssl base64 -d -A
}

# in_cidr16 <first-two-octets> <ip> — true if IP is in that /16. kind's node
# network is always a /16 (e.g. 172.19.0.0/16); the trailing "." in the glob
# stops 172.190.x from matching 172.19. No external tools.
in_cidr16() { case "$2" in "$1".*) return 0 ;; *) return 1 ;; esac; }

# in_gateway_cidr <ip> — inside 172.16.0.0/12, the gateway CIDR the local chart
# overlays allow through the charts' NetworkPolicies (B27.33).
in_gateway_cidr() { case "$1" in 172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;; *) return 1 ;; esac; }

# attacker_get <ip> <port> — curl from the SEC-3 attacker pod (pod-network).
# Echoes "code=<http_code> <body>". A Calico drop => curl -m times out => the
# writer prints code=000 with an empty body; a hit => code=200 + the backend text.
attacker_get() {
  local ip="$1" port="$2" out
  out="$(k -n sec3-attacker exec deploy/attacker -- \
    curl -s -m 4 -w '\n%{http_code}' "http://${ip}:${port}/" 2>/dev/null || true)"
  printf 'code=%s %s' "$(printf '%s\n' "$out" | tail -1)" "$(printf '%s\n' "$out" | head -1)"
}

wait_nodes_ready() {
  section "waiting for all nodes Ready"
  k wait --for=condition=Ready nodes --all --timeout="${1:-240s}" \
    && ok "all nodes Ready" || die "nodes never became Ready (is the CNI installed?)"
}

# wait_rollout <kind/name> <ns> [timeout]
wait_rollout() { k -n "$2" rollout status "$1" --timeout="${3:-240s}"; }

# apply_secret <ns> <type> <name> <create-args...> — idempotent create-or-update
# (create --dry-run | apply), so re-runs never fail on an existing secret.
apply_secret() {
  local ns="$1" typ="$2" name="$3"; shift 3
  k -n "$ns" create secret "$typ" "$name" "$@" --dry-run=client -o yaml | k apply -f -
}

# ep_pod — the current edge-proxy pod name (re-resolved each call, since a flip
# rolls the DaemonSet and invalidates any cached name).
ep_pod() { k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }

# envoy_config_dump <edge-proxy-pod> — fetch the Envoy admin /config_dump. The
# admin is localhost-only in the pod (R7), so reach it via a short-lived
# port-forward. Echoes the JSON (empty string on failure).
envoy_config_dump() {
  local pod="$1" out
  # kubectl directly, not the k() wrapper: backgrounding a function makes $! a
  # subshell, and killing that leaves the port-forward holding 19001, so every
  # later call would read the FIRST pod's config.
  kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$pod" 19001:9901 >/dev/null 2>&1 &
  local pf=$!
  sleep 5
  out="$(curl -s --max-time 8 http://127.0.0.1:19001/config_dump 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true
  wait "$pf" 2>/dev/null || true
  printf '%s' "$out"
}
