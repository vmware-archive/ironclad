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
	"testing"

	"github.com/heptiolabs/ironclad/pkg/audit/types"
)

func TestRequestHeaders(t *testing.T) {
	e := EnrichedEvent{}
	e.Transaction.Request.Headers = map[string]string{
		"foo": "bar",
	}
	headers := e.RequestHeaders()
	if headers.Get("foo") != "bar" {
		t.Error("expected to get something back as a header")
	}
}

func TestGetMessage(t *testing.T) {
	m := types.Message{
		Message: "foo",
		Details: types.Details{
			RuleID: "1234",
		},
	}
	e := EnrichedEvent{}
	e.Transaction.Messages = []types.Message{m}

	if e.GetMessage(0) != nil {
		t.Error("expected not to find anything")
	}

	result := e.GetMessage(1234)
	if result == nil || result.Message != "foo" {
		t.Error("expected to find our message")
	}
}
