{{- define "edge-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-proxy.fullname" -}}
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

{{- define "edge-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-proxy.labels" -}}
helm.sh/chart: {{ include "edge-proxy.chart" . }}
{{ include "edge-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "edge-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edge-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: edge-proxy
{{- end -}}

{{- define "edge-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "edge-proxy.fullname" .) .Values.serviceAccount.name -}}
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
{{- define "edge-proxy.image" -}}
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
selector labels, so the DaemonSet and the Service never pick the test pod up.
*/}}
{{- define "edge-proxy.testLabels" -}}
app.kubernetes.io/name: {{ include "edge-proxy.name" . }}-test
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: helm-test
{{- end -}}
