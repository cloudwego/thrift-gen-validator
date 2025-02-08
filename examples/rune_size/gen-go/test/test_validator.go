// Copyright 2021 CloudWeGo Authors
//
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

package test

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// unused protection
var (
	_ = fmt.Formatter(nil)
	_ = (*bytes.Buffer)(nil)
	_ = (*strings.Builder)(nil)
	_ = reflect.Type(nil)
	_ = (*regexp.Regexp)(nil)
	_ = time.Nanosecond
)

func (p *Example) IsValid() error {
	if len([]rune(p.MaxRuneString)) > int(10) {
		return fmt.Errorf("field MaxRuneString max_rune_size rule failed, current value: %d", len([]rune(p.MaxRuneString)))
	}
	if len([]rune(p.MinRuneString)) < int(10) {
		return fmt.Errorf("field MinRuneString min_rune_size rule failed, current value: %d", len([]rune(p.MinRuneString)))
	}
	for k := range p.KeyValues {
		if len([]rune(k)) > int(10) {
			return fmt.Errorf("field k max_rune_size rule failed, current value: %d", len([]rune(k)))
		}
		if len([]rune(k)) < int(10) {
			return fmt.Errorf("field k min_rune_size rule failed, current value: %d", len([]rune(k)))
		}
	}
	return nil
}
