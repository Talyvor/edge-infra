#!/usr/bin/env bash
# image-scan.sh — no image ships with a known, fixable HIGH or CRITICAL CVE, and
# no image is built on a base that can change under it.
#
#   bash deploy/hack/image-scan.sh scan <tag>
#       scan every first-party image the charts install, at :<tag> — a release
#       such as 1.2.3, or the commit sha a build pushed.
#   bash deploy/hack/image-scan.sh scan <image-ref>...
#       trivy-scan each image (a registry ref such as …/edge-osb@sha256:<hex>, or
#       an image in the local docker daemon) and exit 1 if any carries a HIGH or
#       CRITICAL vulnerability that has a fixed version: OS packages, Go modules
#       and the Go standard library compiled into a binary, Python packages.
#       A vulnerability with no fixed version yet does not fail the scan — there
#       is nothing to upgrade to — and the nightly run of images.yaml fails the
#       morning a fix ships.
#   bash deploy/hack/image-scan.sh bases [Dockerfile...]
#       exit 1 if any FROM in the given Dockerfiles (default: every tracked one)
#       names an image by tag alone. A base must be pinned to its digest —
#       name:tag@sha256:<hex> — so the same commit always builds on the same
#       bytes, and a new base arrives as a reviewed commit that the scan sees.
#   bash deploy/hack/image-scan.sh install <dir>
#       put the pinned, checksum-verified trivy in <dir>.
#
# images.yaml runs `scan` on every image it pushed before the sign job will sign
# any of them, and proves the scan can fail by planting a vulnerable package in
# the OSB image (test/image-scan/planted).
#
# Run: make scan-images TAG=<tag>   (needs trivy, and read access to the packages)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REGISTRY="${RELEASE_REGISTRY:-ghcr.io/talyvor}"

TRIVY_VERSION=0.74.0

die() { echo "image-scan: $*" >&2; exit 1; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

install_trivy() { # dir
	local dir="$1" os arch asset sum tmp
	os="$(uname -s)"
	arch="$(uname -m)"
	# From the release's own trivy_<version>_checksums.txt.
	case "$os-$arch" in
	Linux-x86_64)
		asset=Linux-64bit
		sum=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
		;;
	Darwin-arm64)
		asset=macOS-ARM64
		sum=1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11
		;;
	*) die "no pinned trivy for $os-$arch" ;;
	esac
	tmp="$(mktemp -d)"
	curl -fsSL -o "$tmp/trivy.tar.gz" \
		"https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_${asset}.tar.gz"
	[ "$(sha256 "$tmp/trivy.tar.gz")" = "$sum" ] || die "trivy $TRIVY_VERSION $asset does not match its pinned sha256"
	tar -xzf "$tmp/trivy.tar.gz" -C "$tmp" trivy
	mkdir -p "$dir"
	install -m 0755 "$tmp/trivy" "$dir/"
	rm -rf "$tmp"
	"$dir/trivy" --version | head -1
}

# chart_images — every first-party repository a chart installs.
chart_images() {
	sed -n "s#^[[:space:]]*repository:[[:space:]]*\"\{0,1\}\(${REGISTRY//./\\.}/[^\"[:space:]]*\).*#\1#p" \
		"$REPO"/deploy/helm/*/values.yaml | sort -u
}

scan() { # <tag> | <ref>...
	local ref fail=0 n=0 refs=()
	[ $# -gt 0 ] || die "scan takes a tag or one or more image refs"
	if [ $# = 1 ] && [[ "$1" != */* ]] && [[ "$1" != *:* ]]; then
		[[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "'$1' is not an image tag"
		while IFS= read -r ref; do refs+=("$ref:$1"); done < <(chart_images)
		[ ${#refs[@]} -gt 0 ] || die "no chart names an image under $REGISTRY"
		set -- "${refs[@]}"
	fi
	command -v trivy >/dev/null || die "needs trivy on PATH (bash deploy/hack/image-scan.sh install <dir> puts it there)"
	# One database download for the whole run, not one per image.
	trivy image --download-db-only --no-progress
	for ref in "$@"; do
		n=$((n + 1))
		echo "── $ref"
		if trivy image --skip-db-update --no-progress --scanners vuln \
			--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$ref"; then
			echo "ok    $ref"
		else
			echo "FAIL  $ref: a HIGH or CRITICAL vulnerability with a fixed version (table above)" >&2
			fail=$((fail + 1))
		fi
	done
	[ "$fail" = 0 ] || die "$fail of $n image(s) carry a fixable HIGH or CRITICAL vulnerability"
	echo "all $n image(s) clear of fixable HIGH and CRITICAL vulnerabilities"
}

bases() { # [Dockerfile...]
	local files=() f n=0 bad=0 line w ref stages
	if [ $# -gt 0 ]; then files=("$@"); else
		while IFS= read -r f; do files+=("$REPO/$f"); done < <(git -C "$REPO" ls-files '*Dockerfile*')
	fi
	[ ${#files[@]} -gt 0 ] || die "no Dockerfile to check"
	for f in "${files[@]}"; do
		stages=" scratch "
		while IFS= read -r line; do
			# FROM [--platform=…] <ref> [AS <stage>]
			read -ra w <<<"$line"
			w=("${w[@]:1}")
			while [ ${#w[@]} -gt 0 ] && [[ "${w[0]}" == --* ]]; do w=("${w[@]:1}"); done
			ref="${w[0]:-}"
			[ -n "$ref" ] || continue
			[ ${#w[@]} -lt 3 ] || stages+="$(tr '[:upper:]' '[:lower:]' <<<"${w[2]}") "
			# An earlier stage, or a stage chosen by a build arg, is not a base.
			case "$stages" in *" $(tr '[:upper:]' '[:lower:]' <<<"$ref") "*) continue ;; esac
			case "$ref" in *'$'*) continue ;; esac
			n=$((n + 1))
			if [[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]]; then continue; fi
			echo "FAIL  ${f#"$REPO"/}: FROM $ref is not pinned to a digest" >&2
			bad=$((bad + 1))
		done < <(grep -iE '^[[:space:]]*FROM[[:space:]]' "$f")
	done
	[ "$bad" = 0 ] || die "$bad of $n base image(s) float: pin each as name:tag@sha256:<index digest>"
	echo "all $n base image(s) in ${#files[@]} Dockerfile(s) pinned to a digest"
}

case "${1:-}" in
scan) shift; scan "$@" ;;
bases) shift; bases "$@" ;;
install) [ $# = 2 ] || die "usage: install <dir>"; install_trivy "$2" ;;
*) sed -n '2,28s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
esac
