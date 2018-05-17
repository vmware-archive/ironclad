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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"

	geoip "github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
)

// Handler for a ModSecurity audit event
type Handler interface {
	Handle(*EnrichedEvent) error
}

// Server is a localhost ModSecurity audit event receiver
type Server interface {
	URL() string
	AddHandler(Handler)
}

type server struct {
	// GeoIP database handles
	geoipCity *geoip.Reader
	geoipASN  *geoip.Reader

	listener net.Listener

	handlers      []Handler
	handlersMutex sync.RWMutex
}

func (s *server) AddHandler(h Handler) {
	s.handlersMutex.Lock()
	defer s.handlersMutex.Unlock()
	s.handlers = append(s.handlers, h)
}

// StartServer starts a ModSecurity audit event receiver (in a goroutine)
func StartServer() (Server, error) {
	s := &server{
		handlers: []Handler{},
	}

	// open the GeoIP databases or fail
	geoipCity, err := geoip.Open("/usr/share/GeoIP/GeoLite2-City.mmdb")
	if err != nil {
		return nil, err
	}
	s.geoipCity = geoipCity

	geoipASN, err := geoip.Open("/usr/share/GeoIP/GeoLite2-ASN.mmdb")
	if err != nil {
		return nil, err
	}
	s.geoipASN = geoipASN

	// start a TCP listener on an arbitrary localhost port or fail
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.listener = listener

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/audit", s.handleAuditEvent)
		logrus.WithField("url", s.URL()).Info("started audit event listener")
		http.Serve(s.listener, mux)
	}()

	return s, nil
}

// URL returns the localhost URL where the audit receiver is listening
func (s *server) URL() string {
	if s.listener == nil {
		return ""
	}
	return fmt.Sprintf(
		"http://127.0.0.1:%d/audit",
		s.listener.Addr().(*net.TCPAddr).Port)
}

func (s *server) handleAuditEvent(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logrus.WithError(err).Error("error reading request body")
	}

	// start with the raw event sent by ModSecurity
	var event EnrichedEvent
	if err := json.Unmarshal(body, &event); err != nil {
		logrus.WithError(err).Error("error unmarshaling audit JSON")
	}

	// enrich the event with GeoIP data, if we can
	ipLogger := logrus.WithField("clientIP", event.Transaction.ClientIP)
	clientIP := net.ParseIP(event.Transaction.ClientIP)
	if clientIP == nil {
		ipLogger.Error("could not parse client IP")
	} else {
		cityRecord, err := s.geoipCity.City(clientIP)
		if err != nil {
			ipLogger.Error("could not find client IP in city-level GeoIP database")
		}
		event.GeoIPLookup = cityRecord

		asnRecord, err := s.geoipASN.ASN(clientIP)
		if err != nil {
			ipLogger.Error("could not find client IP in ASN database")
		}
		event.ASNLookup = asnRecord
	}

	// call all the handlers
	s.handlersMutex.RLock()
	defer s.handlersMutex.RUnlock()
	for _, handler := range s.handlers {
		if err := handler.Handle(&event); err != nil {
			logrus.WithError(err).WithField("handler", handler).Error("error handling event")
		}
	}
}
