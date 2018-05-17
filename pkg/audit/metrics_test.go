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

package audit

import (
	"reflect"
	"testing"

	"github.com/heptiolabs/ironclad/pkg/audit/types"
	"github.com/prometheus/client_golang/prometheus"
)

var inboundAnomalyMessage = "Inbound Anomaly Score Exceeded (Total Inbound Score: 4321 - SQLI=1,XSS=2,RFI=3,LFI=4,RCE=5,PHPI=6,HTTP=7,SESS=8): NoScript XSS InjectionChecker: HTML Injection"
var inboundExpectedScores = map[string]int{
	"total": 4321,
	"sqli":  1,
	"xss":   2,
	"rfi":   3,
	"lfi":   4,
	"rce":   5,
	"phpi":  6,
	"http":  7,
	"sess":  8,
}

var outboundAnomalyMessage = "Outbound Anomaly Score Exceeded (Total Score: 1234)"
var outboundExpectedScores = map[string]int{
	"total": 1234,
}

var alertEvent = EnrichedEvent{
	Event: types.Event{
		Transaction: types.Transaction{
			Messages: []types.Message{
				{
					Message: inboundAnomalyMessage,
					Details: types.Details{RuleID: "980130"},
				},
				{
					Message: outboundAnomalyMessage,
					Details: types.Details{RuleID: "980140"},
				},
			},
			Request: types.Request{
				Method: "FOO",
			},
			Response: types.Response{
				HTTPCode: 123,
			},
		},
	},
}

func TestMetricsHandler(t *testing.T) {
	registry := prometheus.NewRegistry()
	handler, err := NewMetricsHandler(registry, "foo")
	if err != nil {
		t.Errorf("could not create metrics handler: %s", err)
	}
	if err := handler.Handle(&alertEvent); err != nil {
		t.Errorf("unexpected error from Handle(): %v", err)
	}
	metrics, err := registry.Gather()
	if err != nil {
		t.Errorf("could not gather metrics: %s", err)
	}
	if len(metrics) != 3 {
		t.Errorf("expected 3 metrics, found %d", len(metrics))
	}
}

func TestGetAnomalyScores(t *testing.T) {
	inboundScores, err := getAnomalyScores(&alertEvent, 980130, inboundAnomalyMessagePat)
	if err != nil {
		t.Errorf("unxpected error getting inbound anomaly scores: %v", err)
	}
	if !reflect.DeepEqual(inboundScores, inboundExpectedScores) {
		t.Errorf("unxpected inbound anomaly scores, found %#v, expected %#v", inboundScores, inboundExpectedScores)
	}

	outboundScores, err := getAnomalyScores(&alertEvent, 980140, outboundAnomalyMessagePat)
	if err != nil {
		t.Errorf("unxpected error getting outbound anomaly scores: %v", err)
	}
	if !reflect.DeepEqual(outboundScores, outboundExpectedScores) {
		t.Errorf("unxpected outbound anomaly scores, found %#v, expected %#v", outboundScores, outboundExpectedScores)
	}
}
