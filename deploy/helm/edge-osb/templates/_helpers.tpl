{{- define "edge-osb.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-osb.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "edge-osb.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-osb.labels" -}}
helm.sh/chart: {{ include "edge-osb.chart" . }}
{{ include "edge-osb.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "edge-osb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edge-osb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: edge-osb
{{- end -}}

{{- define "edge-osb.apiSelectorLabels" -}}
{{ include "edge-osb.selectorLabels" . }}
component: api
{{- end -}}

{{- define "edge-osb.workerSelectorLabels" -}}
{{ include "edge-osb.selectorLabels" . }}
component: worker
{{- end -}}

{{- define "edge-osb.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "edge-osb.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
An image reference. With global.imageRegistry set, the image is pulled from that
registry instead, its path kept: ghcr.io/talyvor/edge-osb becomes
<registry>/talyvor/edge-osb, envoyproxy/envoy <registry>/envoyproxy/envoy
and redis <registry>/library/redis.
Call with (dict "image" <an image: block> "global" $.Values.global).
*/}}
{{- define "edge-osb.image" -}}
{{- $repo := toString .image.repository -}}
{{- with .global.imageRegistry -}}
{{- $parts := splitList "/" $repo -}}
{{- $host := "docker.io" -}}
{{- if and (gt (len $parts) 1) (regexMatch "[.:]|^localhost$" (first $parts)) -}}
{{- $host = first $parts -}}
{{- $parts = rest $parts -}}
{{- end -}}
{{- if and (eq $host "docker.io") (eq (len $parts) 1) -}}
{{- $parts = prepend $parts "library" -}}
{{- end -}}
{{- $repo = printf "%s/%s" (trimSuffix "/" .) (join "/" $parts) -}}
{{- end -}}
{{- printf "%s:%s" $repo (toString .image.tag) -}}
{{- end -}}

{{/*
Labels of this chart's `helm test` pod (templates/tests/). Deliberately not the
selector labels, so the Service, the PodDisruptionBudgets and the NetworkPolicies'
own podSelectors never pick the test pod up; the api NetworkPolicy lets exactly
these labels in, to the port the test checks.
*/}}
{{- define "edge-osb.testLabels" -}}
app.kubernetes.io/name: {{ include "edge-osb.name" . }}-test
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: helm-test
{{- end -}}
