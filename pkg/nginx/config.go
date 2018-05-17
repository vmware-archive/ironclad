// Copyright © 2018 Heptio
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nginx

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"text/template"
	"time"
)

// Config specifies configuration for the nginx instance that runs ModSecurity
type Config struct {
	// ListenPort configures the TCP port where nginx will listen
	ListenPort uint16

	// Backend configures the backend port to which nginx will proxy
	BackendPort uint16

	// TrustedProxyIPRanges configures which upstream IP ranges nginx will trust to send correct X-Forwarded-For headers
	TrustedProxyIPRanges []string

	// AuditReceiverURL configures the HTTP/HTTPS endpoint where ModSecurity will log audit events
	AuditReceiverURL string

	// DetectionOnly puts the proxy into detection only mode (no blocking of attacks)
	DetectionOnly bool

	// PrependedRules configures a list of rules to include before the OWASP Core Rule Set
	PrependedRules []string

	// AppendedRules configures a list of rules to include after the OWASP Core Rule Set
	AppendedRules []string
}

const configPath = "/etc/nginx/conf/nginx.conf"
const configMode = 0644

const prependedRulesPath = "/etc/nginx/conf/ironclad_modsecurity_prepend.conf"
const appendedRulesPath = "/etc/nginx/conf/ironclad_modsecurity_append.conf"

var configTemplate = template.Must(
	template.New("nginx.conf").Option("missingkey=error").Parse(`
daemon off;
user nobody;
worker_processes auto;
worker_cpu_affinity auto;
error_log stderr error;

events {
    worker_connections  1024;
}

http {
    include mime.types;
    default_type  application/octet-stream;
    access_log off;
    gzip on;

    server {
        listen {{.ListenPort}};
        server_name "";
        server_tokens off;

        # proxy all requests to the configured backend
        location / {
            proxy_pass http://127.0.0.1:{{.BackendPort}};
            proxy_set_header X-Request-ID $request_id;
        }

        {{ if .TrustedProxyIPRanges }}
        {{ range .TrustedProxyIPRanges }}
        set_real_ip_from {{.}};
        {{- end }}
        real_ip_header X-Forwarded-For;
        {{- end }}

        # enable ModSecurity and load base (static) ModSecurity configuration
        modsecurity on;
        modsecurity_rules_file '/etc/nginx/conf/modsecurity.conf';

        # load all user-defined and OWASP Core Rule Set rules
        modsecurity_rules_file '` + prependedRulesPath + `';
        include /etc/nginx/conf/modsecurity_crs.conf;
        modsecurity_rules_file '` + appendedRulesPath + `';

        # enable the core ModSecurity engine and configure audit events to go to the localhost audit receiver
        modsecurity_rules '
        SecRuleEngine {{ if .DetectionOnly -}} DetectionOnly {{- else }} On {{- end }}
        SecAuditEngine On
        SecAuditLogType HTTPS
        SecAuditLogRelevantStatus ".*"
        SecAuditLog {{.AuditReceiverURL}}
        SecAuditLogParts ABHZ
        ';

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
`))

func (config *Config) write() error {
	// write out prepended and appended rules to their own files
	if err := writeRulesFile(config.PrependedRules, prependedRulesPath); err != nil {
		return nil
	}
	if err := writeRulesFile(config.AppendedRules, appendedRulesPath); err != nil {
		return nil
	}

	// start with a header with a render timestamp
	var renderedConfig bytes.Buffer
	renderedConfig.WriteString(fmt.Sprintf(
		"# rendered by ironclad/pkg/nginx/config.go on %s",
		time.Now().Format(time.RFC3339Nano)))

	// render the main configuration body
	if err := configTemplate.Execute(&renderedConfig, config); err != nil {
		return err
	}

	// write the config to disk
	if err := ioutil.WriteFile(configPath, renderedConfig.Bytes(), configMode); err != nil {
		return err
	}
	return nil
}

func writeRulesFile(rules []string, path string) error {
	return ioutil.WriteFile(path, []byte(strings.Join(rules, "\n")+"\n"), configMode)
}
