#!/usr/bin/env bash
# kubeconform.sh — everything the charts can render is a valid Kubernetes object
# for the version kind runs (B28.236).
#
# Renders every chart in deploy/helm for its base values, each customer profile
# in deploy/profiles (lite, ha, airgap), the kind values (deploy/local/values, as
# up.sh layers them), and once with every optional resource switched on — the
# NetworkPolicies, the HorizontalPodAutoscalers, the optional images and the
# Prometheus Operator objects. Then validates the lot with kubeconform -strict:
# an unknown field, a wrong type or a duplicate key fails it. `helm template`
# renders the `helm test` pods too, so they are checked with the rest. Custom
# resources are checked against the CRDs catalog at a pinned commit.
#
# Extra args are passed to every `helm template`, and CHARTS (space-separated)
# limits the charts rendered — which is how CI proves the check can go red.
#
# Run: make kubeconform    (or: bash deploy/hack/kubeconform.sh)
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
EXTRA=("$@")
KUBERNETES_VERSION="${KUBERNETES_VERSION:-1.35.0}"   # kind v0.31's node image
CRDS_CATALOG="https://raw.githubusercontent.com/datreeio/CRDs-catalog/fd90051867733c60d32d16450556e9cd18459aef/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

command -v kubeconform >/dev/null || { echo "kubeconform not found on PATH"; exit 1; }

# Values a chart needs to render at all, or to render an optional image.
switches() { # chart
	case "$1" in
	auth-service)
		echo --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/16' --set confidential.enabled=true \
			--set 'confidential.attestation.measurements[0]=00' \
			--set confidential.attestation.trustedKey=kubeconform
		;;
	edge-issuer) echo --set config.activeKid=kubeconform --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/16' ;;
	# NetworkPolicies are on by default and need the nodes' CIDR (B50.8).
	edge-control-plane | edge-osb | edge-ratelimit) echo --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/16' ;;
	edge-datastores)
		echo --set backup.enabled=true \
			--set backup.s3.bucket=kubeconform \
			--set backup.s3.existingSecret=kubeconform
		;;
	esac
}

# Every optional resource on.
everything() { # chart
	local hpa=(--set autoscaling.enabled=true --set autoscaling.maxReplicas=4
		--set autoscaling.targetCPUUtilizationPercentage=80)
	local np=(--set networkPolicy.enabled=true --set 'networkPolicy.gatewayCIDRs[0]=10.0.0.0/8')
	case "$1" in
	edge-proxy | edge-pki) ;;
	edge-datastores) echo --set networkPolicy.enabled=true ;;
	edge-observability) echo --set networkPolicy.enabled=true --set prometheusOperator.enabled=true ;;
	edge-egress | edge-secrets) echo --set networkPolicy.enabled=true "${hpa[@]}" ;;
	edge-osb)
		echo "${np[@]}" --set podDisruptionBudget.minAvailable=1 \
			--set api.autoscaling.enabled=true --set api.autoscaling.maxReplicas=4 \
			--set worker.autoscaling.enabled=true --set worker.autoscaling.maxReplicas=4
		;;
	*) echo "${np[@]}" "${hpa[@]}" ;;
	esac
}

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
fail=0
render() { # chart label args...
	local chart="$1" label="$2"
	shift 2
	if ! helm template "$chart" "$REPO/deploy/helm/$chart" -n infra "$@" ${EXTRA[@]+"${EXTRA[@]}"} \
		>"$OUT/$chart--$label.yaml" 2>"$OUT/err"; then
		echo "FAIL  $chart $label  (helm render error)"
		tail -3 "$OUT/err"
		rm -f "$OUT/$chart--$label.yaml"
		fail=1
	fi
}

for dir in "$REPO"/deploy/helm/*/; do
	chart="$(basename "$dir")"
	case " ${CHARTS:-$chart} " in *" $chart "*) ;; *) continue ;; esac
	suffix="${chart#edge-}"
	# shellcheck disable=SC2046
	render "$chart" base $(switches "$chart")
	# shellcheck disable=SC2046
	render "$chart" everything $(switches "$chart") $(everything "$chart")
	for profile in "$REPO"/deploy/profiles/*/"$chart".yaml; do
		[ -f "$profile" ] || continue
		# shellcheck disable=SC2046
		render "$chart" "profile-$(basename "$(dirname "$profile")")" --values "$profile" $(switches "$chart")
	done
	if [ -f "$REPO/deploy/local/values/values-$suffix.yaml" ]; then
		render "$chart" kind --values "$REPO/deploy/local/values/values-$suffix.yaml"
	fi
done

if ! ls "$OUT"/*.yaml >/dev/null 2>&1; then
	echo "FAIL  nothing rendered"
	exit 1
fi
echo "kubeconform -strict, Kubernetes $KUBERNETES_VERSION, $(ls "$OUT"/*.yaml | wc -l | tr -d ' ') render(s):"
kubeconform -strict -summary -output text -kubernetes-version "$KUBERNETES_VERSION" \
	-schema-location default -schema-location "$CRDS_CATALOG" "$OUT"/*.yaml || fail=1

# The same renders against the B50.8 security checklist, after it proves each of
# its rules can fail.
echo
bash "$REPO/deploy/hack/verify-chart-security.sh" --self-test || fail=1
bash "$REPO/deploy/hack/verify-chart-security.sh" "$OUT" || fail=1

echo
if [ "$fail" -eq 0 ]; then
	echo "OK: every render is valid Kubernetes $KUBERNETES_VERSION."
else
	echo "INVALID: fix the chart above (or the profile that feeds it)."
	exit 1
fi
