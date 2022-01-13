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
	"strings"
	"testing"

	"github.com/cloudwego/thriftgo/parser"
	"github.com/cloudwego/thriftgo/plugin"
	"github.com/cloudwego/thriftgo/semantic"
)

var numericTest = `
struct Numeric {
	1: i64 I64 (vt.gt = "10")
}
`

func Test_generator_generate(t *testing.T) {
	ast, err := parser.ParseString("a.thrift", numericTest)
	if err != nil {
		t.Fatal(err)
	}
	err = semantic.ResolveSymbols(ast)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		req     *plugin.Request
		want    string
		wantErr bool
	}{
		{
			name: "numeric",
			req: &plugin.Request{
				AST:        ast,
				OutputPath: ".",
			},
			want:    `if p.I64 <= int64(10) {`,
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
			if !strings.Contains(got[0].Content, tt.want) {
				t.Errorf("generator.generate() = %v, want %v", got[0].Content, tt.want)
			}
		})
	}
}
