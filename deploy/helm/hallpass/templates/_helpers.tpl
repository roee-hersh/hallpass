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
Name for cluster-scoped resources. Carries the namespace so two releases
with the same name in different namespaces do not collide.
*/}}
{{- define "hallpass.clusterScopedName" -}}
{{- printf "%s-%s-subjectaccessreview" (include "hallpass.fullname" .) .Release.Namespace | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Image reference: repository@digest when a digest is set, else repository:tag.
*/}}
{{- define "hallpass.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
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
{{- if .Values.rbac.subjectAccessReview.create }}
{{- if not .Values.serviceAccount.automountToken }}
{{- fail "rbac.subjectAccessReview.create grants the pod's ServiceAccount a permission it can only use with its token mounted: also set serviceAccount.automountToken=true" }}
{{- end }}
{{- if and (not .Values.serviceAccount.create) (not .Values.serviceAccount.name) }}
{{- fail "rbac.subjectAccessReview.create with serviceAccount.create=false needs serviceAccount.name; binding the namespace's default ServiceAccount would grant the permission to every pod using it" }}
{{- end }}
{{- end }}
{{- end }}
