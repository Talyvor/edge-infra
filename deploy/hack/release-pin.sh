#!/usr/bin/env bash
# release-pin.sh — pin every first-party chart image to ONE tag.
#
#   bash deploy/hack/release-pin.sh <tag>    # rewrite deploy/helm/*/values.yaml
#   bash deploy/hack/release-pin.sh --list   # print the pinned refs, one per line
#
# First-party = a `repository:` under $RELEASE_REGISTRY (default
# ghcr.io/talyvor). The `tag:` line straight after it is the pin; third-
# party images (envoy, digest-pinned) are left alone. --list exits 1 unless every
# first-party image carries the same tag, so a half-pinned set of charts cannot be
# released or tested as one.
#
# The release workflow (.github/workflows/release.yaml) pins the charts to the
# commit it just built and pushed, then runs `make release-e2e`, which pulls
# exactly the refs --list prints and runs the kind e2e on them.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REGISTRY="${RELEASE_REGISTRY:-ghcr.io/talyvor}"
REPO_RE="^[[:space:]]*repository:[[:space:]]*\"?${REGISTRY//./\\.}/"

die() { echo "release-pin: $*" >&2; exit 1; }

# pairs <values.yaml> — "<repository>:<tag>" for each first-party image in it.
pairs() {
	awk -v re="$REPO_RE" '
		repo != "" {
			if ($0 ~ /^[[:space:]]*tag:/) {
				t = $0; sub(/^[[:space:]]*tag:[[:space:]]*/, "", t); sub(/[[:space:]]+#.*$/, "", t); gsub(/"/, "", t)
				print repo ":" t
			} else {
				print FILENAME ": " repo " has no tag: on the next line" > "/dev/stderr"; bad = 1
			}
			repo = ""
		}
		$0 ~ re { repo = $0; sub(/^[[:space:]]*repository:[[:space:]]*/, "", repo); sub(/[[:space:]]+#.*$/, "", repo); gsub(/"/, "", repo) }
		END { exit bad }
	' "$1"
}

list() {
	local f refs="" tags
	for f in "$REPO"/deploy/helm/*/values.yaml; do
		refs+="$(pairs "$f")"$'\n'
	done
	refs="$(printf '%s' "$refs" | sed '/^$/d' | sort -u)"
	[ -n "$refs" ] || die "no chart names an image under $REGISTRY"
	tags="$(printf '%s\n' "$refs" | sed 's/.*://' | sort -u)"
	if [ "$(printf '%s\n' "$tags" | wc -l | tr -d ' ')" != 1 ]; then
		printf '%s\n' "$refs" >&2
		die "the charts pin $(printf '%s\n' "$tags" | wc -l | tr -d ' ') tags, not one — run: bash deploy/hack/release-pin.sh <tag>"
	fi
	printf '%s\n' "$refs"
}

pin() {
	local tag="$1" f tmp n=0
	[[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "'$tag' is not a valid image tag"
	[ "$tag" != latest ] || die "refusing to pin to :latest"
	for f in "$REPO"/deploy/helm/*/values.yaml; do
		tmp="$(mktemp)"
		awk -v re="$REPO_RE" -v tag="$tag" '
			after && /^[[:space:]]*tag:/ {
				ind = $0; sub(/tag:.*/, "", ind)
				cmt = ""; if (match($0, /[[:space:]]+#.*$/)) cmt = substr($0, RSTART)
				print ind "tag: \"" tag "\"" cmt; after = 0; next
			}
			{ after = ($0 ~ re); print }
		' "$f" >"$tmp"
		if ! cmp -s "$f" "$tmp"; then cat "$tmp" >"$f"; n=$((n + 1)); fi
		rm -f "$tmp"
	done
	echo "release-pin: $n values.yaml file(s) rewritten" >&2
	list >/dev/null
}

case "${1:-}" in
"") die "usage: release-pin.sh <tag> | --list" ;;
--list) list ;;
*) pin "$1" ;;
esac
