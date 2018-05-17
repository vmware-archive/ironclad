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
	"strings"

	"github.com/sirupsen/logrus"
)

type loggerHandler struct {
	logger *logrus.Logger
}

// NewLoggerHandler creates an audit event handler that logs via the logrus log stream
func NewLoggerHandler(logger *logrus.Logger) Handler {
	return &loggerHandler{logger: logger}
}

func (l *loggerHandler) Handle(event *EnrichedEvent) error {
	// start with logging at least the client IP (which could be blank)
	log := l.logger.WithFields(logrus.Fields{
		"clientIP":      event.Transaction.ClientIP,
		"txid":          event.Transaction.ID,
		"requestMethod": event.Transaction.Request.Method,
		"requestPath":   event.Transaction.Request.URI,
		"responseCode":  event.Transaction.Response.HTTPCode,
	})

	// annotate with the user agent if available
	userAgent := event.RequestHeaders().Get("User-Agent")
	if userAgent != "" {
		log = log.WithField("userAgent", userAgent)
	}

	// add context related to the geographic location of the IP address, if known
	if event.GeoIPLookup != nil {
		if event.GeoIPLookup.City.Names["en"] != "" {
			// get the English name of the city
			city := event.GeoIPLookup.City.Names["en"]

			// append the first subdivision if there is one (e.g., the US State)
			if len(event.GeoIPLookup.Subdivisions) > 0 && event.GeoIPLookup.Subdivisions[0].IsoCode != "" {
				city = city + ", " + event.GeoIPLookup.Subdivisions[0].IsoCode
			}
			log = log.WithField("city", city)
		}

		if event.GeoIPLookup.Country.IsoCode != "" {
			log = log.WithField("country", event.GeoIPLookup.Country.IsoCode)
		}
	}

	// add context from the Autonomous System (AS) associated with the IP address
	if event.ASNLookup != nil {
		if event.ASNLookup.AutonomousSystemNumber != 0 {
			log = log.WithField("asn", fmt.Sprintf("%d", event.ASNLookup.AutonomousSystemNumber))
		}
		if event.ASNLookup.AutonomousSystemOrganization != "" {
			log = log.WithField("asnOwner", event.ASNLookup.AutonomousSystemOrganization)
		}
	}

	// log a basic message that we processed a request (even if it didn't generate any alerts)
	// this is done at Debug level so it'll be disabled by default
	// (enable with `logLevel: debug` in the config)
	log.WithFields(logrus.Fields{
		"type":          "request",
		"matchingRules": len(event.Transaction.Messages),
	}).Debug("processed request")

	// log a message for each alert message generated
	for _, msg := range event.Transaction.Messages {
		context := logrus.Fields{
			"type":   "alert",
			"ruleID": msg.Details.RuleID,
		}

		if msg.Details.Data != "" {
			context["matchData"] = strings.TrimPrefix(msg.Details.Data, "Matched Data: ")
		}
		log.WithFields(context).Info(msg.Message)
	}
	return nil
}
