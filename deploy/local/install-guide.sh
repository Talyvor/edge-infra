#!/usr/bin/env bash
# install-guide.sh — docs/install.md and then docs/upgrade.md, run as written, on
# a throwaway kind cluster.
#
#   make kind-install-guide                    # == deploy/local/install-guide.sh
#   KEEP_CLUSTER=1 make kind-install-guide     # leave the cluster up afterwards
#
# Every ```sh block of the guide is extracted in order and run in ONE bash shell
# with `set -euo pipefail`, exactly as a customer would paste them, so a command
# that fails or a check that does not hold stops the run. Nothing in a block is
# rewritten or skipped. What this script provides is only what the guide's
# "What you need" asks the reader to bring:
#
#   - the cluster: kind, 1 control-plane + 2 workers, Calico as the network
#     plugin (up.sh Phase 1), reached through a kubeconfig holding only it;
#   - the release: every first-party image built from the working tree, tagged
#     ghcr.io/talyvor/<name>:$EDGE_VERSION and loaded onto the nodes, and
#     the guide's `git clone --branch v$EDGE_VERSION https://github.com/…` served
#     from a local copy of HEAD tagged v$EDGE_VERSION (git url.insteadOf), so it
#     clones the commit under test. Local runs test the COMMITTED HEAD: commit
#     before you run it;
#   - the four variables: PROFILE (ha — deploy/profiles/ha), EDGE_VERSION,
#     NODE_CIDR (kind's docker network) and GATEWAY (127.0.0.1 — the worker
#     kind-config.yaml publishes :80 from).
#
# Then the ha profile is checked to be what runs: every service at the copies the
# profile gives it, each copy Ready, spread over both workers with no node
# holding more than one copy more than the other.
#
# docs/upgrade.md then runs the same way, from the directory the guide installed
# from, to a second release NEW_VERSION: the same images under a second tag and a
# second git tag, so its commands must roll every first-party image to that tag.
# The ha check runs again after it.
#
# Then the cluster is deleted, whether the run passed or failed.
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-install}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq openssl curl git

PROFILE=ha
EDGE_VERSION="${EDGE_VERSION:-0.0.0-install-guide}"
NEW_VERSION="${NEW_VERSION:-0.0.1-install-guide}"
CLONE_URL=https://github.com/Talyvor/edge-infra.git
FIRST_PARTY="edge-control-plane edge-issuer edge-ratelimit edge-secrets edge-migrate edge-attest edge-osb auth-service"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (kind delete cluster --name $CLUSTER_NAME) or pick another CLUSTER_NAME"
fi

WORK="$(mktemp -d)"
started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  # The guide's port-forwards, if a block failed before it killed them.
  pkill -f "port-forward svc/edge-(osb|issuer) 1808" 2>/dev/null || true
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "FAILED (exit $rc) — cluster state before teardown"
    k get pods -A -o wide 2>/dev/null || true
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up (kubeconfig $WORK/kubeconfig); delete it with: kind delete cluster --name $CLUSTER_NAME"
  else
    kind delete cluster --name "$CLUSTER_NAME" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
    rm -rf "$WORK"
  fi
  if [ "$rc" = 0 ]; then
    ok "kind-install-guide PASSED in $(( ($(date +%s) - started) / 60 )) min — every sh block of docs/install.md and docs/upgrade.md ran, cluster removed"
  else
    printf '%s  X kind-install-guide FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT

# ---- a page's blocks ----------------------------------------------------------
# doc_script <page> <min-blocks> <out> — each ```sh block of docs/<page>, in
# order, preceded by an echo of where it starts, as one `set -euo pipefail`
# script. A fence with any other info string (yaml, text, none) is not a command
# and is not run.
doc_script() {
  local page="$1" min="$2" out="$3" n
  n="$(grep -c '^```sh[[:space:]]*$' "$REPO_ROOT/docs/$page")"
  [ "$n" -ge "$min" ] || die "docs/$page has $n sh blocks, fewer than $min — the extraction is broken"
  {
    echo 'set -euo pipefail'
    awk -v page="$page" '
      /^```sh[[:space:]]*$/ { inblk = 1; n++; printf "printf \"\\n\\033[1;34m==> docs/%s:%d (block %d)\\033[0m\\n\"\n", page, NR, n; next }
      inblk && /^```[[:space:]]*$/ { inblk = 0; next }
      inblk { print }
      END { if (inblk) { print "docs/" page ": unterminated sh block" > "/dev/stderr"; exit 1 } }
    ' "$REPO_ROOT/docs/$page"
    printf 'printf "\\n%%s\\n" "docs/%s: all blocks ran"\n' "$page"
  } >"$out"
  echo "$n"
}

# run_doc <page> <blocks> <script> <dir> [VAR=value...] — run it in <dir> as the
# reader would, against the test cluster only; pass only if every block ran.
run_doc() {
  local page="$1" blocks="$2" script="$3" dir="$4" ran; shift 4
  section "docs/$page — $blocks blocks, as written"
  ( cd "$dir" &&
    env KUBECONFIG="$WORK/kubeconfig" GIT_CONFIG_GLOBAL="$WORK/gitconfig" "$@" \
      bash "$script" ) | tee "$WORK/$page.log"
  grep -q "^docs/$page: all blocks ran\$" "$WORK/$page.log" || die "docs/$page stopped before its last block"
  ran="$(grep -c "==> docs/$page:" "$WORK/$page.log")"
  [ "$ran" = "$blocks" ] || die "$ran of the $blocks blocks of docs/$page ran"
  ok "all $blocks sh blocks of docs/$page ran and every check in them held"
}

section "extracting the sh blocks of docs/install.md and docs/upgrade.md"
GUIDE_BLOCKS="$(doc_script install.md 10 "$WORK/install.sh")"
UPGRADE_BLOCKS="$(doc_script upgrade.md 4 "$WORK/upgrade.sh")"
ok "install.md: $GUIDE_BLOCKS blocks; upgrade.md: $UPGRADE_BLOCKS blocks"

# release <version> — the images under ghcr.io/talyvor/<name>:<version> on
# the nodes, and the commit under test as git tag v<version> in the mirror.
release() {
  local name
  for name in $FIRST_PARTY; do
    docker tag "$name:$IMAGE_TAG" "ghcr.io/talyvor/$name:$1"
    kind load docker-image --name "$CLUSTER_NAME" "ghcr.io/talyvor/$name:$1"
  done
  git -C "$REPO_ROOT" push --quiet "$WORK/mirror.git" "HEAD:refs/tags/v$1"
  ok "release $1: eight images on the nodes, git tag v$1 = $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
}

# ha_running — each service the guide installs runs the copies the ha profile
# gives it (read back from the release's own values, so a guide that dropped the
# profile fails here), every copy Ready, on two or more nodes, with no node
# holding more than one copy more than another.
ha_running() {
  local rel want sel got
  for rel in edge-control-plane edge-issuer auth-service edge-osb edge-secrets; do
    if [ "$rel" = edge-osb ]; then
      want="$(h get values "$rel" -n infra -o json | jq -r '.api.replicaCount // empty')"
      sel="app=edge-osb,component=api"
    else
      want="$(h get values "$rel" -n infra -o json | jq -r '.replicaCount // empty')"
      sel="app=$rel"
    fi
    [ -n "$want" ] && [ "$want" -ge 2 ] \
      || die "$rel was not installed with the $PROFILE profile (replicaCount '${want}')"
    # "<copies Ready> <nodes> <most on one node> <fewest on one node>"
    got="$(k -n infra get pods -l "$sel" -o json | jq -r '
      [.items[] | select(.metadata.deletionTimestamp == null)
                | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
                | .spec.nodeName]
      | group_by(.) | map(length) | "\(add // 0) \(length) \(max // 0) \(min // 0)"')"
    set -- $got
    [ "$1" = "$want" ] || die "$rel: $1 of its $want copies Ready"
    [ "$2" -ge 2 ] || die "$rel: all $want copies on one node"
    [ $(($3 - $4)) -le 1 ] || die "$rel: $3 copies on one node and $4 on another"
    ok "$rel: $want copies Ready, over $2 nodes ($3 and $4)"
  done
}

# ---- what the reader brings: the cluster --------------------------------------
section "the cluster: kind '$CLUSTER_NAME' with Calico (up.sh Phase 1)"
bash "$LOCAL_DIR/up.sh" phase1_cluster
kind get kubeconfig --name "$CLUSTER_NAME" >"$WORK/kubeconfig"
NODE_CIDR="$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' | grep -E '^[0-9]+\.' | head -1)"
[ -n "$NODE_CIDR" ] || die "could not read the IPv4 subnet of docker network 'kind'"
ok "nodes are in $NODE_CIDR"

# ---- what the reader brings: the release --------------------------------------
section "the images, built from the working tree"
bash "$LOCAL_DIR/up.sh" build_local_images
# The one public image the guide names by tag alone, preloaded so a Docker Hub
# rate limit cannot fail the run. The digest-pinned ones (envoy, busybox, curl,
# the datastores) are left to the nodes: `kind load` of an image@digest leaves an
# `import-…` record in the node's containerd that the container then fails to
# start from ("failed to check if this is a checkpoint image").
{ docker pull "$ECHO_IMAGE" >/dev/null && kind load docker-image --name "$CLUSTER_NAME" "$ECHO_IMAGE" >/dev/null; } \
  || warn "could not preload $ECHO_IMAGE — a node will pull it"
ok "images loaded"

section "the release $EDGE_VERSION, served in place of $CLONE_URL"
git init --quiet --bare "$WORK/mirror.git"
git -C "$WORK/mirror.git" config receive.shallowUpdate true   # CI checks out one commit
printf '[url "file://%s/mirror.git"]\n\tinsteadOf = %s\n' "$WORK" "$CLONE_URL" >"$WORK/gitconfig"
release "$EDGE_VERSION"

# ---- the pages -------------------------------------------------------------------
mkdir "$WORK/reader"
run_doc install.md "$GUIDE_BLOCKS" "$WORK/install.sh" "$WORK/reader" \
  PROFILE="$PROFILE" EDGE_VERSION="$EDGE_VERSION" NODE_CIDR="$NODE_CIDR" GATEWAY=127.0.0.1

section "the $PROFILE profile is what runs"
ha_running

section "the release $NEW_VERSION, to upgrade to"
release "$NEW_VERSION"
run_doc upgrade.md "$UPGRADE_BLOCKS" "$WORK/upgrade.sh" "$WORK/reader/edge-infra" \
  PROFILE="$PROFILE" NEW_VERSION="$NEW_VERSION"

section "the $PROFILE profile still runs after the upgrade"
ha_running
