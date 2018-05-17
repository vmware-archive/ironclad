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

package types

import (
	"encoding/json"
	"testing"
)

const exampleJSON = `
{
	"transaction": {
	  "client_ip": "198.51.100.1",
	  "time_stamp": "Thu Sep  7 16:04:26 2017",
	  "server_id": "0217b5de9728b276c0b9640addcb6a78dc139e21",
	  "client_port": 0,
	  "host_ip": "198.51.100.1",
	  "host_port": 80,
	  "id": "150480026629.757077",
	  "request": {
		"method": "GET",
		"http_version": 1.1,
		"uri": "/hello/world?x=%3Cscript%3Ealert(1)%3C/script%3E;",
		"headers": {
		  "Host": "test",
		  "User-Agent": "curl/7.54.0",
		  "Accept": "*/*",
		  "X-Forwarded-For": "198.51.100.1"
		}
	  },
	  "response": {
		"http_code": 403
	  },
	  "producer": {
		"modsecurity": "ModSecurity v3.0.0rc1 (Linux)",
		"connector": "ModSecurity-nginx v0.1.1-beta",
		"secrules_engine": "Enabled",
		"components": [
		  "OWASP_CRS/3.0.2\""
		]
	  },
	  "messages": [
		{
		  "message": "XSS Attack Detected via libinjection",
		  "details": {
			"match": "detected XSS using libinjection.",
			"reference": "v19,26t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls",
			"ruleId": "941100",
			"file": "/etc/nginx/conf/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
			"lineNumber": "17",
			"data": "Matched Data: x-forwarded-for found within ARGS:x: <script>alert(1)</script>;",
			"severity": "2",
			"ver": "OWASP_CRS/3.0.0",
			"rev": "2",
			"tags": [
			  "application-multi",
			  "language-multi",
			  "platform-multi",
			  "attack-xss",
			  "OWASP_CRS/WEB_ATTACK/XSS",
			  "WASCTC/WASC-8",
			  "WASCTC/WASC-22",
			  "OWASP_TOP_10/A3",
			  "OWASP_AppSensor/IE1",
			  "CAPEC-242"
			],
			"maturity": "1",
			"accuracy": "9"
		  }
		},
		{
		  "message": "XSS Filter - Category 1: Script Tag Vector",
		  "details": {
			"match": "Matched \"Operator ` + "`" + `Rx' with parameter ` + "`" + `(?i)([<＜]script[^>＞]*[>＞][\\s\\S]*?)' against variable ` + "`" + `ARGS:x' (Value: ` + "`" + `<script>alert(1)</script>;' )",
			"reference": "o0,8o0,8v19,26t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls",
			"ruleId": "941110",
			"file": "/etc/nginx/conf/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
			"lineNumber": "63",
			"data": "Matched Data: <script> found within ARGS:x: <script>alert(1)</script>;",
			"severity": "2",
			"ver": "OWASP_CRS/3.0.0",
			"rev": "2",
			"tags": [
			  "application-multi",
			  "language-multi",
			  "platform-multi",
			  "attack-xss",
			  "OWASP_CRS/WEB_ATTACK/XSS",
			  "WASCTC/WASC-8",
			  "WASCTC/WASC-22",
			  "OWASP_TOP_10/A3",
			  "OWASP_AppSensor/IE1",
			  "CAPEC-242"
			],
			"maturity": "4",
			"accuracy": "9"
		  }
		},
		{
		  "message": "NoScript XSS InjectionChecker: HTML Injection",
		  "details": {
			"match": "Matched \"Operator ` + "`" + `Rx' with parameter ` + "`" + `(?i)<[^\\w<>]*(?:[^<>\\\"'\\s]*:)?[^\\w<>]*(?:\\W*?s\\W*?c\\W*?r\\W*?i\\W*?p\\W*?t|\\W*?f\\W*?o\\W*?r\\W*?m|\\W*?s\\W*?t\\W*?y\\W*?l\\W*?e|\\W*?s\\W*?v\\W*?g|\\W*?m\\W*?a\\W*?r\\W*?q\\W*?u\\W*?e\\W*?e|(?:\\W*?l\\W*?i\\W*?n\\W*?k|\\W*?o (3246 characters omitted)' against variable ` + "`" + `ARGS:x' (Value: ` + "`" + `<script>alert(1)</script>;' )",
			"reference": "o0,7o16,8v19,26t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls",
			"ruleId": "941160",
			"file": "/etc/nginx/conf/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
			"lineNumber": "195",
			"data": "Matched Data: <script found within ARGS:x: <script>alert(1)</script>;",
			"severity": "2",
			"ver": "OWASP_CRS/3.0.0",
			"rev": "2",
			"tags": [
			  "application-multi",
			  "language-multi",
			  "platform-multi",
			  "attack-xss",
			  "OWASP_CRS/WEB_ATTACK/XSS",
			  "WASCTC/WASC-8",
			  "WASCTC/WASC-22",
			  "OWASP_TOP_10/A3",
			  "OWASP_AppSensor/IE1",
			  "CAPEC-242"
			],
			"maturity": "1",
			"accuracy": "8"
		  }
		},
		{
		  "message": "Inbound Anomaly Score Exceeded (Total Score: 15)",
		  "details": {
			"match": "Matched \"Operator ` + "`" + `Ge' with parameter ` + "`" + `%{tx.inbound_anomaly_score_threshold}' against variable ` + "`" + `TX:ANOMALY_SCORE' (Value: ` + "`" + `15' )",
			"reference": "",
			"ruleId": "949110",
			"file": "/etc/nginx/conf/owasp-modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
			"lineNumber": "36",
			"data": "",
			"severity": "2",
			"ver": "",
			"rev": "",
			"tags": [
			  "application-multi",
			  "language-multi",
			  "platform-multi",
			  "attack-generic"
			],
			"maturity": "0",
			"accuracy": "0"
		  }
		},
		{
		  "message": "Inbound Anomaly Score Exceeded (Total Inbound Score: 15 - SQLI=0,XSS=15,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): NoScript XSS InjectionChecker: HTML Injection",
		  "details": {
			"match": "Matched \"Operator ` + "`" + `Ge' with parameter ` + "`" + `%{tx.inbound_anomaly_score_threshold}' against variable ` + "`" + `TX:INBOUND_ANOMALY_SCORE' (Value: ` + "`" + `15' )",
			"reference": "",
			"ruleId": "980130",
			"file": "/etc/nginx/conf/owasp-modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf",
			"lineNumber": "61",
			"data": "",
			"severity": "0",
			"ver": "",
			"rev": "",
			"tags": [
			  "event-correlation"
			],
			"maturity": "0",
			"accuracy": "0"
		  }
		}
	  ]
	}
  }
`

func TestUnmarshal(t *testing.T) {
	var event Event
	if err := json.Unmarshal([]byte(exampleJSON), &event); err != nil {
		t.Errorf("failed to unmarshal event: %v", err)
	}

	marshaled, err := json.Marshal(&event)
	if err != nil {
		t.Errorf("failed to marshal event: %v", err)
	}

	original := normalizeJSON(t, exampleJSON)
	roundtripped := normalizeJSON(t, string(marshaled))

	if original != roundtripped {
		t.Errorf("failed roundtrip JSON")
		t.Logf("original:\n%s\n\n", original)
		t.Logf("roundtripped:\n%s\n\n", roundtripped)
	}
}

func normalizeJSON(t *testing.T, original string) string {
	var unmarshaled interface{}
	if err := json.Unmarshal([]byte(original), &unmarshaled); err != nil {
		t.Fatalf("couldn't unmarshal: %v", err)
	}

	remarshaled, err := json.MarshalIndent(unmarshaled, "", "    ")
	if err != nil {
		t.Fatalf("couldn't remarshal: %v", err)
	}
	return string(remarshaled)
}
