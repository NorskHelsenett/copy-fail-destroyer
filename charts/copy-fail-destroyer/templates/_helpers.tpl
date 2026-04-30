{{- define "copy-fail-destroyer.name" -}}
{{- .Chart.Name }}
{{- end }}

{{- define "copy-fail-destroyer.labels" -}}
app.kubernetes.io/name: {{ include "copy-fail-destroyer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "copy-fail-destroyer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "copy-fail-destroyer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "copy-fail-destroyer.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
