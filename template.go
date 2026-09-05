package main

// tpl renders the plugins.intel.nsrl result as a Markdown block, extending the
// old template (Found / Not Found) with the exact RDSv3 match details and a
// graceful error branch.
const tpl = `#### NSRL Database
{{- if .Results.Found }}
 - Found :white_check_mark:
 - File: {{.Results.FileName}}
 - SHA256: {{.Results.Sha256}}
 - Size: {{.Results.FileSize}}
{{- else if .Results.Error }}
 - Error: {{.Results.Error}}
{{- else }}
 - Not Found :question:
{{ end -}}
`
