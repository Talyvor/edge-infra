{{- define "edge-datastores.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-datastores.labels" -}}
helm.sh/chart: {{ include "edge-datastores.chart" . }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The in-cluster host of a bundled store. The subcharts name their Service
<release>-<chart>, so this is the same name. */}}
{{- define "edge-datastores.host" -}}
{{- printf "%s-%s.%s.svc.cluster.local" .root.Release.Name .store .root.Release.Namespace -}}
{{- end -}}

{{/* A credential for a bundled store: the value set in values.yaml, else the one
already in the connection Secret (so an upgrade keeps it), else a new random
one. Args: (list $ $existingSecret "KEY" $setValue). */}}
{{- define "edge-datastores.credential" -}}
{{- $existing := index . 1 -}}
{{- $key := index . 2 -}}
{{- $set := index . 3 -}}
{{- if $set -}}
{{- $set -}}
{{- else if and $existing $existing.data (hasKey $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}

{{/*
An image reference. With global.imageRegistry set, the image is pulled from that
registry instead, its path kept: ghcr.io/talyvor/edge-osb becomes
<registry>/talyvor/edge-osb, envoyproxy/envoy <registry>/envoyproxy/envoy
and redis <registry>/library/redis.
Call with (dict "image" <an image: block> "global" $.Values.global).
*/}}
{{- define "edge-datastores.image" -}}
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
The pod of a backup or a restore Job: one init container, then one container,
sharing /backup. Call with (dict "root" $ "component" "backup"|"restore"
"first" <script> "firstImage" "postgres"|"s3" "then" <script> "thenImage" …).
*/}}
{{- define "edge-datastores.backupPod" -}}
{{- $root := .root -}}
metadata:
  labels:
    app.kubernetes.io/name: {{ $root.Chart.Name }}
    app.kubernetes.io/instance: {{ $root.Release.Name }}
    app.kubernetes.io/component: {{ .component }}
spec:
  restartPolicy: Never
  {{- with $root.Values.global.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  initContainers:
    {{- include "edge-datastores.backupContainer" (dict "root" $root "script" .first "image" .firstImage) | nindent 4 }}
  containers:
    {{- include "edge-datastores.backupContainer" (dict "root" $root "script" .then "image" .thenImage) | nindent 4 }}
  volumes:
    - name: scripts
      configMap:
        name: {{ $root.Release.Name }}-backup-scripts
    - name: backup
      emptyDir: {}
    - name: tmp
      emptyDir: {}
{{- end -}}

{{/* One container of a backup or restore pod: the Postgres client image (its
postgres uid) or the S3 client image (a nonroot uid), with what its script needs. */}}
{{- define "edge-datastores.backupContainer" -}}
{{- $root := .root -}}
{{- $b := $root.Values.backup -}}
{{- $img := index $b.images .image -}}
- name: {{ .script }}
  image: {{ include "edge-datastores.image" (dict "image" $img "global" $root.Values.global) | quote }}
  imagePullPolicy: {{ $img.pullPolicy }}
  command: ["/bin/sh", "/scripts/{{ .script }}.sh"]
  securityContext:
    runAsUser: {{ ternary 70 65532 (eq .image "postgres") }}
    runAsGroup: {{ ternary 70 65532 (eq .image "postgres") }}
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
  env:
    {{- if eq .image "postgres" }}
    {{- $dbs := concat $b.databases $b.extraDatabases }}
    - name: DB_COUNT
      value: {{ len $dbs | quote }}
    {{- range $i, $db := $dbs }}
    - name: DB_{{ $i }}_NAME
      value: {{ required "backup: every database needs a name" $db.name | quote }}
    - name: DB_{{ $i }}_OPTIONAL
      value: {{ ternary "true" "false" (default false $db.optional) | quote }}
    - name: DB_{{ $i }}_DSN
      valueFrom:
        secretKeyRef:
          name: {{ default $root.Values.global.datastores.secretName $db.secretName }}
          key: {{ required (printf "backup: database %s needs the key of its connection URL" $db.name) $db.key }}
          {{- if $db.optional }}
          optional: true
          {{- end }}
    {{- end }}
    {{- else }}
    - name: AWS_ACCESS_KEY_ID
      valueFrom:
        secretKeyRef: { name: {{ $b.s3.existingSecret }}, key: AWS_ACCESS_KEY_ID }
    - name: AWS_SECRET_ACCESS_KEY
      valueFrom:
        secretKeyRef: { name: {{ $b.s3.existingSecret }}, key: AWS_SECRET_ACCESS_KEY }
    - name: AWS_DEFAULT_REGION
      value: {{ $b.s3.region | quote }}
    {{- with $b.s3.endpoint }}
    - name: AWS_ENDPOINT_URL
      value: {{ . | quote }}
    {{- end }}
    # Checksums only where S3 requires them, which every S3-compatible store accepts.
    - name: AWS_REQUEST_CHECKSUM_CALCULATION
      value: when_required
    - name: AWS_RESPONSE_CHECKSUM_VALIDATION
      value: when_required
    - name: S3_BUCKET
      value: {{ $b.s3.bucket | quote }}
    - name: S3_PREFIX
      value: {{ $b.s3.prefix | quote }}
    - name: S3_PATH_STYLE
      value: {{ ternary "true" "false" $b.s3.forcePathStyle | quote }}
    - name: RESTORE_FROM
      value: {{ $b.restoreFrom | quote }}
    {{- end }}
  {{- with $b.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: scripts
      mountPath: /scripts
      readOnly: true
    - name: backup
      mountPath: /backup
    - name: tmp
      mountPath: /tmp
{{- end -}}
