#!/usr/bin/env bash
# supply-chain.sh — sign every image, attest its SBOM and provenance, verify both.
#
#   bash deploy/hack/supply-chain.sh verify <tag>
#       verify every first-party image the charts install, at :<tag> — a release
#       such as 1.2.3, or the commit sha a build pushed.
#   bash deploy/hack/supply-chain.sh verify <image-ref>...
#       the same for explicit refs: ghcr.io/…/edge-osb:1.2.3 or …@sha256:<hex>.
#     Each image must carry all three of these, each made by this repo's
#     images.yaml workflow, or the command exits 1:
#       a cosign signature           cosign verify
#       an SPDX SBOM made by syft    cosign verify-attestation --type spdxjson
#       SLSA v1 provenance           cosign verify-attestation --type slsaprovenance1
#   bash deploy/hack/supply-chain.sh sign <image>@sha256:<hex>
#       CI only (images.yaml) — needs the job's GitHub OIDC token. Signs the
#       digest, then attests its SBOM and its provenance to it.
#   bash deploy/hack/supply-chain.sh provenance
#       print the SLSA v1 provenance predicate for this GitHub Actions run.
#   bash deploy/hack/supply-chain.sh install <dir>
#       put the pinned, checksum-verified cosign and syft in <dir>.
#
# Keyless: there is no signing key to leak or rotate. cosign trades the job's
# OIDC token for a short-lived Fulcio certificate naming the workflow, signs, and
# records the signature in the public Rekor log. Verifying pins that name, so a
# signature made by any other repository, workflow or ref is refused:
#   issuer    https://token.actions.githubusercontent.com
#   identity  https://github.com/$SIGNER_REPO/.github/workflows/images.yaml@<ref>
# where <ref> is refs/heads/main or a refs/tags/v<SemVer> release tag.
# The certificate must also name $SIGNER_REPO as the repository the run was in.
# SIGNER_REF=<ref> pins one exact ref instead (CI pins its own run's ref, which is
# refs/pull/<n>/merge on a pull request), and SIGNER_SHA=<sha> also pins the
# commit the workflow ran at — in the certificate and in the provenance.
# `verify <tag>` sets them from the tag: 1.2.3 needs SIGNER_REF=refs/tags/v1.2.3,
# and a 40-hex commit tag needs SIGNER_SHA=<that sha>.
#
# Run: make verify-images TAG=<tag>   (needs cosign and jq, and read access to the packages)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Since 12 Oct 2026 the repository is Talyvor/edge-infra and its images are under ghcr.io/talyvor.
# An image built before then is under ghcr.io/gaboracnicolai and was signed by gaboracnicolai/edge-infra:
# verify one with RELEASE_REGISTRY=ghcr.io/gaboracnicolai SIGNER_REPO=gaboracnicolai/edge-infra.
REGISTRY="${RELEASE_REGISTRY:-ghcr.io/talyvor}"
SIGNER_REPO="${SIGNER_REPO:-Talyvor/edge-infra}"
ISSUER=https://token.actions.githubusercontent.com
WORKFLOW=.github/workflows/images.yaml

COSIGN_VERSION=v2.6.5
SYFT_VERSION=1.54.0

die() { echo "supply-chain: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "needs $1 on PATH (bash deploy/hack/supply-chain.sh install <dir> puts cosign and syft there)"; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

install_tools() { # dir
	local dir="$1" os arch cosign_sum syft_sum tmp
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	arch="$(uname -m)"
	case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
	# From each release's own checksums file.
	case "$os-$arch" in
	linux-amd64)
		cosign_sum=c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644
		syft_sum=54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860
		;;
	darwin-arm64)
		cosign_sum=4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab
		syft_sum=7e0bdad94c569fc6d5785c9a657bbae3d4c4e140ccb5eace3d0b5b6bc2b6dbcf
		;;
	*) die "no pinned cosign and syft for $os-$arch" ;;
	esac
	tmp="$(mktemp -d)"
	curl -fsSL -o "$tmp/cosign" "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-$os-$arch"
	curl -fsSL -o "$tmp/syft.tar.gz" "https://github.com/anchore/syft/releases/download/v$SYFT_VERSION/syft_${SYFT_VERSION}_${os}_${arch}.tar.gz"
	[ "$(sha256 "$tmp/cosign")" = "$cosign_sum" ] || die "cosign $COSIGN_VERSION $os-$arch does not match its pinned sha256"
	[ "$(sha256 "$tmp/syft.tar.gz")" = "$syft_sum" ] || die "syft $SYFT_VERSION $os-$arch does not match its pinned sha256"
	tar -xzf "$tmp/syft.tar.gz" -C "$tmp" syft
	mkdir -p "$dir"
	install -m 0755 "$tmp/cosign" "$tmp/syft" "$dir/"
	rm -rf "$tmp"
	"$dir/cosign" version 2>&1 | grep '^GitVersion'
	"$dir/syft" version | grep '^Version'
}

# provenance — the predicate GitHub's own build type defines
# (https://actions.github.io/buildtypes/workflow/v1), from the run's environment:
# which workflow ran, at which ref and commit, triggered how, on which runner.
provenance() {
	local v wf
	for v in GITHUB_SERVER_URL GITHUB_REPOSITORY GITHUB_WORKFLOW_REF GITHUB_REF GITHUB_SHA GITHUB_EVENT_NAME \
		GITHUB_REPOSITORY_ID GITHUB_REPOSITORY_OWNER_ID GITHUB_RUN_ID GITHUB_RUN_ATTEMPT RUNNER_ENVIRONMENT; do
		[ -n "${!v:-}" ] || die "$v is unset — provenance describes a GitHub Actions run"
	done
	# GITHUB_WORKFLOW_REF is <owner>/<repo>/<path>@<ref>: the top-level workflow
	# (release.yaml when it calls images.yaml).
	wf="${GITHUB_WORKFLOW_REF#"$GITHUB_REPOSITORY"/}"
	jq -n \
		--arg server "$GITHUB_SERVER_URL" --arg repo "$GITHUB_REPOSITORY" \
		--arg path "${wf%%@*}" --arg wfref "${wf#*@}" \
		--arg ref "$GITHUB_REF" --arg sha "$GITHUB_SHA" --arg event "$GITHUB_EVENT_NAME" \
		--arg repo_id "$GITHUB_REPOSITORY_ID" --arg owner_id "$GITHUB_REPOSITORY_OWNER_ID" \
		--arg run "$GITHUB_RUN_ID" --arg attempt "$GITHUB_RUN_ATTEMPT" --arg runner "$RUNNER_ENVIRONMENT" '{
		buildDefinition: {
			buildType: "https://actions.github.io/buildtypes/workflow/v1",
			externalParameters: {workflow: {ref: $wfref, repository: ($server + "/" + $repo), path: $path}},
			internalParameters: {github: {
				event_name: $event, repository_id: $repo_id,
				repository_owner_id: $owner_id, runner_environment: $runner}},
			resolvedDependencies: [{uri: ("git+" + $server + "/" + $repo + "@" + $ref), digest: {gitCommit: $sha}}]
		},
		runDetails: {
			builder: {id: ("https://github.com/actions/runner/" + $runner)},
			metadata: {invocationId: ($server + "/" + $repo + "/actions/runs/" + $run + "/attempts/" + $attempt)}
		}
	}'
}

sign() { # image@sha256:<hex>
	local ref="$1" tmp
	[[ "$ref" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]] || die "sign takes <image>@sha256:<hex>, not '$ref' — a tag can move between the push and the signature"
	need cosign
	need syft
	need jq
	tmp="$(mktemp -d)"
	cosign sign --yes "$ref"
	# The SBOM is the linux/amd64 variant's; the arm64 one is built from the same
	# sources and dependency locks.
	syft scan "registry:$ref" --platform linux/amd64 -o "spdx-json=$tmp/sbom.spdx.json"
	cosign attest --yes --type spdxjson --predicate "$tmp/sbom.spdx.json" "$ref"
	provenance >"$tmp/provenance.json"
	# The predicate type as a URI, not cosign's slsaprovenance1 shorthand: the
	# shorthand re-encodes the predicate through cosign's own struct, which
	# renames the spec's invocationId to invocationID. The URI keeps it verbatim,
	# and verify-attestation --type slsaprovenance1 matches the same URI.
	cosign attest --yes --type https://slsa.dev/provenance/v1 --predicate "$tmp/provenance.json" "$ref"
	echo "signed $ref: signature, SPDX SBOM of $(jq '.packages | length' "$tmp/sbom.spdx.json") packages, SLSA v1 provenance"
	rm -rf "$tmp"
}

# chart_images — every first-party repository a chart installs.
chart_images() {
	sed -n "s#^[[:space:]]*repository:[[:space:]]*\"\{0,1\}\(${REGISTRY//./\\.}/[^\"[:space:]]*\).*#\1#p" \
		"$REPO"/deploy/helm/*/values.yaml | sort -u
}

ID=()
signer() {
	local at=""
	[ -z "${SIGNER_SHA:-}" ] || at=" at $SIGNER_SHA"
	if [ -n "${SIGNER_REF:-}" ]; then echo "https://github.com/$SIGNER_REPO/$WORKFLOW@$SIGNER_REF$at"; else
		echo "https://github.com/$SIGNER_REPO/$WORKFLOW@refs/{heads/main,tags/v<SemVer>}$at"; fi
}
identity() {
	# The repository is pinned on its own as well as in the identity: images.yaml
	# is a reusable workflow, and another repository calling it would be issued a
	# certificate with this same identity but its own repository.
	ID=(--certificate-oidc-issuer "$ISSUER" --certificate-github-workflow-repository "$SIGNER_REPO")
	if [ -n "${SIGNER_REF:-}" ]; then
		ID+=(--certificate-identity "https://github.com/$SIGNER_REPO/$WORKFLOW@$SIGNER_REF")
	else
		ID+=(--certificate-identity-regexp "^https://github\\.com/${SIGNER_REPO//./\\.}/\\.github/workflows/images\\.yaml@refs/(heads/main|tags/v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?)\$")
	fi
	[ -z "${SIGNER_SHA:-}" ] || ID+=(--certificate-github-workflow-sha "$SIGNER_SHA")
}

# statements <image@digest> <cosign type> <predicate type> — the in-toto
# statements of that type, verified, whose subject is the digest; one per line.
statements() {
	local hex="${1##*@sha256:}"
	cosign verify-attestation "${ID[@]}" --type "$2" "$1" 2>"$ERR" |
		jq -c --arg t "$3" --arg d "$hex" '.payload | @base64d | fromjson
			| select(.predicateType == $t and any(.subject[]; .digest.sha256 == $d))'
}

verify_one() { # ref
	local ref="$1" repo sig digest pinned sbom pkgs prov commits
	repo="${ref%%@*}"
	case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
	if ! sig="$(cosign verify "${ID[@]}" "$ref" 2>"$ERR")"; then
		echo "FAIL  $ref: no signature verified as made by $(signer)" >&2
		sed 's/^/      /' "$ERR" >&2
		return 1
	fi
	digest="$(jq -r '.[0].critical.image."docker-manifest-digest"' <<<"$sig")"
	pinned="$repo@$digest"
	if ! sbom="$(statements "$pinned" spdxjson https://spdx.dev/Document)" || [ -z "$sbom" ]; then
		echo "FAIL  $pinned: signed, but no SPDX SBOM attested by the same signer" >&2
		sed 's/^/      /' "$ERR" >&2
		return 1
	fi
	pkgs="$(jq -s 'map(.predicate.packages | length) | max' <<<"$sbom")"
	if [ "$pkgs" -lt 1 ]; then
		echo "FAIL  $pinned: its SBOM lists no package" >&2
		return 1
	fi
	if ! prov="$(statements "$pinned" slsaprovenance1 https://slsa.dev/provenance/v1)" || [ -z "$prov" ]; then
		echo "FAIL  $pinned: signed, but no SLSA v1 provenance attested by the same signer" >&2
		sed 's/^/      /' "$ERR" >&2
		return 1
	fi
	commits="$(jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit' <<<"$prov" | sort -u)"
	if [ -n "${SIGNER_SHA:-}" ] && ! grep -qx "$SIGNER_SHA" <<<"$commits"; then
		echo "FAIL  $pinned: provenance names commit ${commits//$'\n'/ }, want $SIGNER_SHA" >&2
		return 1
	fi
	echo "ok    $pinned"
	echo "      signed by   $(jq -r '.[0].optional.Subject' <<<"$sig")"
	echo "      sbom        $pkgs packages (SPDX, syft)"
	echo "      provenance  built from $(jq -r '.predicate.buildDefinition.resolvedDependencies[0].uri' <<<"$prov" | head -1)" \
		"at ${commits//$'\n'/ } by $(jq -r '.predicate.runDetails.metadata.invocationId' <<<"$prov" | head -1)"
}

verify() { # <tag> | <ref>...
	local refs=() r fail=0 n=0
	[ $# -gt 0 ] || die "verify takes a tag or one or more image refs"
	need cosign
	need jq
	if [ $# = 1 ] && [[ "$1" != */* ]]; then
		[[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "'$1' is not an image tag"
		# Bind the check to the tag: a release tag must be signed by that
		# release's run, and a commit-sha tag by a run at that commit.
		if [ -z "${SIGNER_REF:-}" ] && [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then SIGNER_REF="refs/tags/v$1"; fi
		if [ -z "${SIGNER_SHA:-}" ] && [[ "$1" =~ ^[0-9a-f]{40}$ ]]; then SIGNER_SHA="$1"; fi
		while IFS= read -r r; do refs+=("$r:$1"); done < <(chart_images)
		[ ${#refs[@]} -gt 0 ] || die "no chart names an image under $REGISTRY"
	else
		refs=("$@")
	fi
	identity
	ERR="$(mktemp)"
	for r in "${refs[@]}"; do
		n=$((n + 1))
		verify_one "$r" || fail=$((fail + 1))
	done
	rm -f "$ERR"
	[ "$fail" = 0 ] || die "$fail of $n image(s) failed verification against $(signer)"
	echo "all $n image(s) signed, with an SBOM and SLSA provenance, by $(signer)"
}

case "${1:-}" in
verify) shift; verify "$@" ;;
sign) [ $# = 2 ] || die "usage: sign <image>@sha256:<hex>"; sign "$2" ;;
provenance) provenance ;;
install) [ $# = 2 ] || die "usage: install <dir>"; install_tools "$2" ;;
*) sed -n '2,20s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
esac
