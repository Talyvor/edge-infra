#!/usr/bin/env bash
# verify-image-pins.sh — no chart runs an image on the floating "latest" tag.
#
# Renders every chart in deploy/helm for base defaults and each customer profile
# in deploy/profiles, and fails (exit 1) if any rendered image is :latest,
# untagged (which pulls latest) or has an empty tag. A digest (@sha256:) or a
# fixed tag passes. Images behind a switch are switched on for the render (the
# auth-service attest init container, the issuer's required activeKid), so an
# optional image is checked too, not only the default set (edge-datastores'
# backup images included).
#
# Extra args are passed to every `helm template` — `--set image.tag=latest`
# must make this fail, which is how CI proves the check can go red.
#
# With IMAGE_REGISTRY set, every chart is rendered with
# global.imageRegistry=$IMAGE_REGISTRY and it also fails if any rendered image
# is not pulled from that registry (B28.229). A profile that sets
# global.imageRegistry (airgap) is held to its own registry the same way.
#
# Run: make verify-image-pins    (or: bash deploy/hack/verify-image-pins.sh)
#      make verify-image-registry
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
EXTRA=("$@")
REGISTRY="${IMAGE_REGISTRY:-}"
[ -n "$REGISTRY" ] && EXTRA=(--set "global.imageRegistry=$REGISTRY" ${EXTRA[@]+"${EXTRA[@]}"})

# Values that make a chart render every image it can run.
switches() { # chart
	case "$1" in
	auth-service)
		echo --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/16' --set confidential.enabled=true \
			--set 'confidential.attestation.measurements[0]=00' \
			--set confidential.attestation.trustedKey=verify-image-pins
		;;
	edge-issuer) echo --set config.activeKid=verify-image-pins --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/16' ;;
	# NetworkPolicies are on by default and need the nodes' CIDR (B50.8).
	edge-control-plane | edge-osb | edge-ratelimit) echo --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/16' ;;
	edge-datastores)
		echo --set backup.enabled=true \
			--set backup.s3.bucket=verify-image-pins \
			--set backup.s3.existingSecret=verify-image-pins
		;;
	esac
}

fail=0
offreg=0
checked=0
check() { # chart label overlay-relpath(optional)
	local chart="$1" label="$2" overlay="${3:-}" want="$REGISTRY"
	local args=("$chart" "$REPO/deploy/helm/$chart")
	[ -n "$overlay" ] && args+=(--values "$REPO/$overlay")
	[ -z "$want" ] && [ -n "$overlay" ] &&
		want="$(sed -n 's/^  imageRegistry:[[:space:]]*//p' "$REPO/$overlay" | head -1)"
	# shellcheck disable=SC2207
	args+=($(switches "$chart"))
	local out
	if ! out="$(helm template "${args[@]}" ${EXTRA[@]+"${EXTRA[@]}"} 2>&1)"; then
		echo "FAIL  $chart $label  (helm render error)"
		echo "$out" | tail -3
		fail=1
		return
	fi
	local images bad=()
	images="$(sed -n 's/^[[:space:]-]*image:[[:space:]]*//p' <<<"$out" | sed 's/[[:space:]]*#.*$//; s/^"//; s/"$//' | sort -u)"
	if [ -z "$images" ]; then
		echo "FAIL  $chart $label  (rendered no image)"
		fail=1
		return
	fi
	while IFS= read -r img; do
		checked=$((checked + 1))
		if [ -n "$want" ] && [[ "$img" != "$want"/* ]]; then
			bad+=("$img (not from $want)")
			offreg=1
			continue
		fi
		case "$img" in *@sha256:*) continue ;; esac
		local name="${img##*/}"
		case "$name" in
		*:latest | *:) bad+=("$img") ;;
		*:*) ;;
		*) bad+=("$img (untagged)") ;;
		esac
	done <<<"$images"
	if [ ${#bad[@]} -eq 0 ]; then
		echo "PASS  $chart $label  ($(wc -l <<<"$images" | tr -d ' ') image(s))"
	else
		echo "FAIL  $chart $label  $([ "$offreg" -eq 1 ] && echo refused || echo floating): ${bad[*]}"
		fail=1
	fi
}

for dir in "$REPO"/deploy/helm/*/; do
	chart="$(basename "$dir")"
	check "$chart" "base"
	for profile in "$REPO"/deploy/profiles/*/"$chart".yaml; do
		[ -f "$profile" ] || continue
		check "$chart" "profile $(basename "$(dirname "$profile")")" "${profile#"$REPO"/}"
	done
done

echo
if [ "$fail" -eq 0 ]; then
	echo "OK: $checked rendered image reference(s), none on a floating tag."
	[ -z "$REGISTRY" ] || echo "OK: every one is pulled from $REGISTRY."
elif [ "$offreg" -eq 1 ]; then
	echo "IMAGE NOT FROM ITS REGISTRY: render it through the chart's <chart>.image helper."
	exit 1
else
	echo "FLOATING IMAGE: pin the image(s) above to a SHA tag or digest."
	exit 1
fi
