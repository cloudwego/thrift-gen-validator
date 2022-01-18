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

package validator

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/thriftgo/parser"
	"github.com/cloudwego/thriftgo/plugin"
	"github.com/cloudwego/thriftgo/semantic"
)

var numericTest = `
struct Numeric {
	1: i64 I64 (vt.gt = "10")
	2: i64 time (vt.gt = "@add(@now_unix_nano(), 1000)")
} (vt.assert = "@equal($I64, 12)", vt.assert = "@equal(@mod($I64, 10), 0)")
`

func Test_generator_generate(t *testing.T) {
	numericAST, err := parser.ParseString("a.thrift", numericTest)
	if err != nil {
		t.Fatal(err)
	}
	err = semantic.ResolveSymbols(numericAST)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		req     *plugin.Request
		wants   []string
		wantErr bool
	}{
		{
			name: "numeric",
			req: &plugin.Request{
				AST:        numericAST,
				OutputPath: ".",
			},
			wants: []string{
				`if p.I64 <= int64(10) {`,
				`_src := int(time.Now().UnixNano()) + int(1000)`,
				`if p.Time <= int64(_src) {`,
				`if !(int(p.I64) == int(12)) {`,
				`if !(int(int(p.I64) % int(10)) == int(0)) {`,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGenerator(tt.req)
			got, err := g.generate()
			if (err != nil) != tt.wantErr {
				t.Errorf("generator.generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for _, want := range tt.wants {
				if !strings.Contains(got[0].Content, want) {
					t.Errorf("generator.generate() = %v, want %v", got[0].Content, want)
				}
			}
			fmt.Println(got[0].Content)
		})
	}
}
