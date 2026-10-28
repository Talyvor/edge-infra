#!/usr/bin/env bash
# verify-chart-security.sh — every rendered manifest meets the B50.8 checklist.
#
#   bash deploy/hack/verify-chart-security.sh <dir>   # check <dir>/<chart>--<label>.yaml
#   bash deploy/hack/verify-chart-security.sh --self-test
#
# kubeconform.sh renders every chart (base, every optional resource on, every
# profile, the kind values) and hands its output directory here. Per pod:
# Pod Security "restricted" (runAsNonRoot, readOnlyRootFilesystem,
# allowPrivilegeEscalation false, capabilities drop ALL, seccomp RuntimeDefault),
# CPU and memory requests and limits, no hostPath, hostNetwork, hostPID, hostIPC
# or privileged, automountServiceAccountToken false, and every image pinned by
# digest — or, for first-party images (…/talyvor/<name>, from ghcr.io or the
# airgap mirror), by the commit SHA release-pin.sh writes and cosign signs.
# RBAC: no wildcard verb, resource or API group, no binding to cluster-admin,
# admin or edit. Every Ingress carries TLS and HSTS. Every base render that runs
# a server pod also renders a NetworkPolicy, so the defaults are default-deny
# (a hostNetwork pod is outside NetworkPolicy, and a Helm hook — `helm test`, a
# migration — only connects out). Every chart's values.yaml has no
# secret value in its defaults.
#
# A pod that genuinely needs one exception (edge-proxy's Envoy runs hostNetwork
# to serve on every node's own address) names it, with the reason, in the pod
# annotation edge.talyvor.com/security-exception: "<rule>: <why>". The rule
# names are the ones this script prints.
#
# --self-test renders nothing: it checks testdata/insecure--base.yaml, which breaks
# every rule once, and fails unless every rule fires — so a rule that can never
# fail is caught here, not in a cluster.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REGISTRY="${RELEASE_REGISTRY:-ghcr.io/talyvor}"
command -v yq >/dev/null || { echo "yq not found on PATH"; exit 1; }
command -v jq >/dev/null || { echo "jq not found on PATH"; exit 1; }

# Every problem in one rendered file, one per line: "<rule> <kind>/<name>: <detail>".
# $base is true for a chart's base render, where its defaults must already be safe.
# shellcheck disable=SC2016 # a jq program, not shell
JQ='
def pod:
  if .kind == "Pod" then {meta: .metadata, spec: .spec}
  elif (.kind | IN("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job")) then {meta: .spec.template.metadata, spec: .spec.template.spec}
  elif .kind == "CronJob" then {meta: .spec.jobTemplate.spec.template.metadata, spec: .spec.jobTemplate.spec.template.spec}
  else empty end;
def wild: any(.[]?; . == "*");
[.[] | select(. != null and type == "object")] as $docs
| ($docs | map(select(.kind == "NetworkPolicy")) | length) as $netpols
| $docs[]
| "\(.kind)/\(.metadata.name)" as $id
| (
    ( pod
      | (.meta.annotations["edge.talyvor.com/security-exception"] // "") as $ex
      | .spec as $s
      | ( ( [ if $s.hostNetwork == true then "hostNetwork" else empty end,
            if $s.hostPID == true then "hostPID" else empty end,
            if $s.hostIPC == true then "hostIPC" else empty end,
            ($s.volumes[]? | select(.hostPath) | "hostPath volume \(.name)"),
            if $s.automountServiceAccountToken != false then "automountServiceAccountToken not false" else empty end
          ][] | "pod \($id): \(.)" ),
        ( ($s.containers + ($s.initContainers // []))[]
          | .name as $c | (.securityContext // {}) as $sc | ($s.securityContext // {}) as $psc
          | [ if ($sc.runAsNonRoot // $psc.runAsNonRoot) != true then "runAsNonRoot not true" else empty end,
              if ($sc.runAsUser // $psc.runAsUser) == 0 then "runAsUser 0" else empty end,
              if $sc.readOnlyRootFilesystem != true then "readOnlyRootFilesystem not true" else empty end,
              if $sc.allowPrivilegeEscalation != false then "allowPrivilegeEscalation not false" else empty end,
              if $sc.privileged == true then "privileged" else empty end,
              if (($sc.capabilities.drop // []) | index("ALL")) == null then "capabilities do not drop ALL" else empty end,
              ($sc.capabilities.add[]? | select(. != "NET_BIND_SERVICE") | "capability \(.) added"),
              if (($sc.seccompProfile.type // $psc.seccompProfile.type) | IN("RuntimeDefault", "Localhost")) | not then "seccompProfile not RuntimeDefault" else empty end,
              (["requests", "limits"][] as $k | ["cpu", "memory"][] as $r
                | select(.resources[$k][$r] == null) | "no \($r) \($k)"),
              if ($kind | not) and (.image | test("@sha256:[0-9a-f]{64}$") | not)
                 and (.image | test("/" + $owner + "/[^/:]+:[0-9a-f]{40}$") | not)
              then "image \(.image) not pinned by digest" else empty end
            ][] | "container \($id)/\($c): \(.)" )
      ) | select(. as $p | $ex | contains($p | sub("^[a-z]+ [^:]*: "; "")) | not)
    ),
    ( select(.kind | IN("Role", "ClusterRole")) | .rules[]?
      | select((.verbs | wild) or (.resources | wild) or (.apiGroups | wild))
      | "rbac \($id): wildcard in \(.)" ),
    ( select(.kind | IN("RoleBinding", "ClusterRoleBinding"))
      | select(.roleRef.name | IN("cluster-admin", "admin", "edit"))
      | "rbac \($id): bound to \(.roleRef.name)" ),
    ( select(.kind == "Ingress")
      | (if (.spec.tls // []) == [] then "ingress \($id): no tls" else empty end),
        (if ([.metadata.annotations // {} | to_entries[] | "\(.key) \(.value)"] | any(test("hsts|strict-transport-security"; "i"))) | not
         then "ingress \($id): no HSTS" else empty end) ),
    ( select($base and $netpols == 0)
      | select([pod | select(.spec.hostNetwork != true and (.meta.annotations["helm.sh/hook"] // "") == "")] | length > 0)
      | "networkpolicy \($id): the base render has no NetworkPolicy" )
  )
'

# check_file <file> <base> <kind> — print problems, prefixed with the file.
# The kind render runs images built on this machine (:local), so it skips the pin.
check_file() {
	yq -o=json -I=0 '.' "$1" | jq -rs --arg owner "${REGISTRY##*/}" --argjson base "$2" --argjson kind "$3" "$JQ" |
		sed "s|^|$(basename "$1" .yaml)  |"
}

# check_values <values.yaml> — a default that looks like a secret value.
check_values() {
	yq -o=json '.' "$1" | jq -r '
		paths(scalars) as $p | getpath($p) as $v
		| ($p | map(tostring) | join(".")) as $k
		| select($v | type == "string" and length > 0)
		| select($p[-1] | tostring | test("(password|passwd|secret|token|apikey|api_key|privatekey|private_key|credential)$"; "i"))
		| select($p[-1] | tostring | test("^existing|(Name|Ref)$") | not)
		| "\($k): a secret value in the defaults"' | sed "s|^|values $1  |"
}

run() { # dir
	local out=() f base kind
	for f in "$1"/*.yaml; do
		[ -f "$f" ] || continue
		base=false kind=false
		case "$f" in *--base.yaml) base=true ;; *--kind.yaml) kind=true ;; esac
		while IFS= read -r line; do out+=("$line"); done < <(check_file "$f" "$base" "$kind")
	done
	# shellcheck disable=SC2086 # VALUES, or the default, is a glob on purpose
	for f in ${VALUES:-$REPO/deploy/helm/*/values.yaml}; do
		while IFS= read -r line; do out+=("$line"); done < <(check_values "$f")
	done
	printf '%s\n' ${out[@]+"${out[@]}"}
	[ ${#out[@]} -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then
	got="$(VALUES="$HERE/testdata/insecure-values.yaml" run "$HERE/testdata")"
	miss=0
	for rule in hostNetwork hostPID hostIPC "hostPath volume" "automountServiceAccountToken not false" \
		"runAsNonRoot not true" "runAsUser 0" "readOnlyRootFilesystem not true" \
		"allowPrivilegeEscalation not false" privileged "capabilities do not drop ALL" \
		"capability SYS_ADMIN added" "seccompProfile not RuntimeDefault" "no cpu requests" \
		"no memory limits" "not pinned by digest" "wildcard in" "bound to cluster-admin" \
		"no tls" "no HSTS" "has no NetworkPolicy" "a secret value in the defaults"; do
		grep -qF "$rule" <<<"$got" || { echo "self-test: rule never fired: $rule"; miss=1; }
	done
	# The exception annotation waives exactly the rule it names, on its own pod.
	grep -q "Deployment/excepted: hostNetwork" <<<"$got" && { echo "self-test: the exception annotation was ignored"; miss=1; }
	grep -q "Deployment/excepted: hostPID" <<<"$got" || { echo "self-test: the exception annotation waived a rule it did not name"; miss=1; }
	[ "$miss" -eq 0 ] && echo "OK: every chart-security rule fires on testdata/insecure--base.yaml."
	exit "$miss"
fi

[ -d "${1:-}" ] || { echo "usage: $0 <rendered-dir> | --self-test"; exit 2; }
if run "$1"; then
	echo "OK: every render meets the chart-security checklist (B50.8)."
else
	echo "INSECURE: fix the chart above, or name a real need in edge.talyvor.com/security-exception."
	exit 1
fi
