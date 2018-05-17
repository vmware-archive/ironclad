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
	"fmt"
	"regexp"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// inboundAnomalyScoreExceededRuleID is the OWASP Core Rule Set rule ID for "Inbound Anomaly Score Exceeded [...]"
const inboundAnomalyScoreExceededRuleID = 980130

// outboundAnomalyScoreExceededRuleID is the OWASP Core Rule Set rule ID for "Outbound Anomaly Score Exceeded [...]"
const outboundAnomalyScoreExceededRuleID = 980140

// anomalyBuckets are the histogram buckets for inbound/outbound anomaly scores (20 buckets from 1 to 20)
var anomalyBuckets = prometheus.LinearBuckets(0.0, 1.0, 20)

var inboundAnomalyMessagePat = regexp.MustCompile(
	`Inbound Anomaly Score Exceeded \(Total Inbound Score: (?P<total>\d+) - SQLI=(?P<sqli>\d+),XSS=(?P<xss>\d+),RFI=(?P<rfi>\d+),LFI=(?P<lfi>\d+),RCE=(?P<rce>\d+),PHPI=(?P<phpi>\d+),HTTP=(?P<http>\d+),SESS=(?P<sess>\d+)\)`,
)

var outboundAnomalyMessagePat = regexp.MustCompile(
	`Outbound Anomaly Score Exceeded \(Total Score: (?P<total>\d+)\)`,
)

// metricsHandler is a handler that records metrics into a Prometheus registry
type metricsHandler struct {
	requestsTotal prometheus.CounterVec
	alertsTotal   prometheus.CounterVec
	anomalyScores prometheus.HistogramVec
}

// NewMetricsHandler creates a PrometheusAuditMetrics with the specified registry and namespace
func NewMetricsHandler(registry prometheus.Registerer, namespace string) (Handler, error) {
	result := &metricsHandler{}

	result.requestsTotal = *prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Request count by method and response code.",
		},
		[]string{"request_method", "response_code"},
	)
	if err := registry.Register(result.requestsTotal); err != nil {
		return nil, err
	}

	result.alertsTotal = *prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "alerts_by_rule_total",
			Help:      "Alert count by ModSecurity rule ID.",
		},
		[]string{"rule_id"},
	)
	if err := registry.Register(result.alertsTotal); err != nil {
		return nil, err
	}

	result.anomalyScores = *prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "anomaly_scores",
			Help: fmt.Sprintf(
				"Anomaly scores of all requests (from OWASP CRS rules %d and %d).",
				inboundAnomalyScoreExceededRuleID,
				outboundAnomalyScoreExceededRuleID),
			Buckets: anomalyBuckets,
		},
		[]string{"type"},
	)
	if err := registry.Register(result.anomalyScores); err != nil {
		return nil, err
	}

	return result, nil
}

// Handle an audit event by recording a set of Prometheus metrics
func (p *metricsHandler) Handle(event *EnrichedEvent) error {

	// count request/response pairs by method and response code
	requestsTotal, err := p.requestsTotal.GetMetricWith(prometheus.Labels{
		"request_method": event.Transaction.Request.Method,
		"response_code":  strconv.Itoa(event.Transaction.Response.HTTPCode),
	})
	if err != nil {
		return err
	}
	requestsTotal.Inc()

	// count matching rules by ID
	for _, msg := range event.Transaction.Messages {
		alertsTotal, err := p.alertsTotal.GetMetricWith(prometheus.Labels{
			"rule_id": msg.Details.RuleID,
		})
		if err != nil {
			return err
		}
		alertsTotal.Inc()
	}

	// record a histogram of inbound anomaly scores
	inboundAnomalyScores, err := getAnomalyScores(
		event, inboundAnomalyScoreExceededRuleID, inboundAnomalyMessagePat)
	if err != nil {
		return err
	}
	for anomalyType, score := range inboundAnomalyScores {
		histogram, err := p.anomalyScores.GetMetricWithLabelValues("inbound_" + anomalyType)
		if err != nil {
			return err
		}
		histogram.Observe(float64(score))
	}

	// record a histogram of outbound anomaly scores
	outboundAnomalyScores, err := getAnomalyScores(
		event, outboundAnomalyScoreExceededRuleID, outboundAnomalyMessagePat)
	if err != nil {
		return err
	}
	for anomalyType, score := range outboundAnomalyScores {
		histogram, err := p.anomalyScores.GetMetricWithLabelValues("outbound_" + anomalyType)
		if err != nil {
			return err
		}
		histogram.Observe(float64(score))

	}

	return nil
}

// getAnomalyScores takes an audit event, a rule ID to look for, and a regex
// pattern with named capture groups. It uses the capture group names to build
// a map from "type" to anomaly score, and pulls the matching scores from the
// audit event.
func getAnomalyScores(event *EnrichedEvent, ruleID int, pat *regexp.Regexp) (map[string]int, error) {
	scores := make(map[string]int)

	// start with everything set to zero (based on the names of the capture groups)
	for _, name := range pat.SubexpNames() {
		if name == "" {
			continue
		}
		scores[name] = 0
	}

	msg := event.GetMessage(ruleID)
	if msg == nil {
		// if there is no anomaly rule firing on this event, report the zero scores
		return scores, nil
	}

	// match with the provided regex pattern
	parts := pat.FindStringSubmatch(msg.Message)
	if parts == nil || len(pat.SubexpNames()) != len(parts) {
		return nil, fmt.Errorf("anomaly rule message didn't match expected format")
	}

	// loop over all the named capture groups
	for i, name := range pat.SubexpNames() {
		if name == "" {
			continue
		}

		// grab the capture group value, convert to an int, and add it into the score
		score, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil, fmt.Errorf("anomaly rule message had invalid integer")
		}
		scores[name] = score
	}

	return scores, nil
}
