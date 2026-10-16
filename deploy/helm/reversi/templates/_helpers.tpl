{{- define "reversi.name" -}}{{ .Release.Name }}-reversi{{- end -}}
{{- define "reversi.labels" -}}
app.kubernetes.io/name: reversi
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "reversi.manifestsCM" -}}{{ if .Values.manifests.existingConfigMap }}{{ .Values.manifests.existingConfigMap }}{{ else }}{{ include "reversi.name" . }}-manifests{{ end }}{{- end -}}
{{- define "reversi.policyCM" -}}{{ if .Values.policy.existingConfigMap }}{{ .Values.policy.existingConfigMap }}{{ else }}{{ include "reversi.name" . }}-policy{{ end }}{{- end -}}
{{- define "reversi.env" -}}
- { name: PORT, value: {{ .Values.server.port | quote }} }
- { name: HOST, value: "0.0.0.0" }
- { name: REVERSI_ENV, value: {{ .Values.server.environment | quote }} }
- { name: REVERSI_STORE, value: {{ .Values.store.kind | quote }} }
- { name: REVERSI_CONSOLE, value: {{ .Values.server.console | quote }} }
{{- if .Values.server.logJson }}
- { name: REVERSI_LOG, value: json }
{{- end }}
{{- if .Values.server.secureCookies }}
- { name: REVERSI_SECURE_COOKIES, value: "1" }
{{- end }}
{{- if .Values.registry.persistence.enabled }}
- { name: REVERSI_MANIFESTS, value: /state/manifests }
- { name: REVERSI_POLICY, value: /state/policy }
{{- else }}
{{- if or .Values.manifests.existingConfigMap .Values.manifests.inline }}
- { name: REVERSI_MANIFESTS, value: /config/manifests }
{{- end }}
{{- if or .Values.policy.existingConfigMap .Values.policy.inline }}
- { name: REVERSI_POLICY, value: /config/policy/policy.yaml }
{{- end }}
{{- end }}
{{- if .Values.keys.existingSecret }}
- { name: REVERSI_KEYS, value: /config/keys/{{ .Values.keys.key }} }
{{- end }}
{{- if eq .Values.store.kind "postgres" }}
- name: REVERSI_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ required "store.databaseUrlSecret.name is required for the postgres store" .Values.store.databaseUrlSecret.name }}, key: {{ .Values.store.databaseUrlSecret.key }} } }
{{- end }}
{{- if .Values.signing.existingSecret }}
- { name: REVERSI_SIGNING_KEY, value: /config/signing/signing.pem }
{{- end }}
{{- if .Values.oidc.enabled }}
- { name: REVERSI_OIDC_ISSUER, value: {{ .Values.oidc.issuer | quote }} }
- { name: REVERSI_OIDC_AUDIENCE, value: {{ .Values.oidc.audience | quote }} }
- { name: REVERSI_OIDC_ROLE_MAP, value: {{ .Values.oidc.roleMap | toJson | quote }} }
{{- end }}
{{- range .Values.extraEnv }}
- {{ toJson . }}
{{- end }}
{{- end -}}
