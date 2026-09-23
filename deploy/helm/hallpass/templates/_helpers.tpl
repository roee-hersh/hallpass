{{/*
Expand the name of the chart.
*/}}
{{- define "hallpass.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "hallpass.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "hallpass.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "hallpass.labels" -}}
helm.sh/chart: {{ include "hallpass.chart" . }}
{{ include "hallpass.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "hallpass.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hallpass.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "hallpass.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hallpass.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the API key: the user's or the chart's own.
*/}}
{{- define "hallpass.apiKeySecretName" -}}
{{- if .Values.apiKey.existingSecret }}
{{- .Values.apiKey.existingSecret }}
{{- else }}
{{- include "hallpass.fullname" . }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap holding hallpass.yaml: the user's or the chart's own.
*/}}
{{- define "hallpass.configMapName" -}}
{{- if .Values.existingConfigMap }}
{{- .Values.existingConfigMap }}
{{- else }}
{{- include "hallpass.fullname" . }}
{{- end }}
{{- end }}

{{/*
Image reference.
*/}}
{{- define "hallpass.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Fail early on a values combination that would produce a pod that cannot start.
*/}}
{{- define "hallpass.validate" -}}
{{- if and .Values.apiKey.existingSecret .Values.apiKey.value }}
{{- fail "set only one of apiKey.existingSecret and apiKey.value" }}
{{- end }}
{{- if and (not .Values.apiKey.existingSecret) (not .Values.apiKey.value) }}
{{- fail "an API key is required: set apiKey.existingSecret (a Secret you manage) or apiKey.value (for a try-out), e.g. --set apiKey.value=change-me" }}
{{- end }}
{{- end }}
