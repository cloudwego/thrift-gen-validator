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
	goParser "go/parser"
	"go/token"
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

var numericTestGoType = `
type Numeric struct {
	I64 int64
	Time int64
}
`

var stringTest = `
struct StringTest {
	1: string Str (vt.pattern = "\d{4}-\\d{2}-\\\d{2}")
}
`

var stringTestGoType = `
type StringTest struct {
	Str String
}
`

func parseGoFile(src string) error {
	fset := token.NewFileSet()
	_, err := goParser.ParseFile(fset, "", src, goParser.AllErrors)
	return err
}

func Test_generator_generate(t *testing.T) {
	tests := []struct {
		name      string
		idl       string
		goTypeDef string
		wants     []string
		wantErr   bool
	}{
		{
			name:      "numeric",
			idl:       numericTest,
			goTypeDef: numericTestGoType,
			wants: []string{
				`if p.I64 <= int64(10) {`,
				`_src := int(time.Now().UnixNano()) + int(1000)`,
				`if p.Time <= int64(_src) {`,
				`if !(int(p.I64) == int(12)) {`,
				`if !(int(int(p.I64) % int(10)) == int(0)) {`,
			},
			wantErr: false,
		},
		{
			name:      "string",
			idl:       stringTest,
			goTypeDef: stringTestGoType,
			wants: []string{
				`"\\d{4}-\\d{2}-\\\\d{2}"`,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseString("validator.thrift", tt.idl)
			if err != nil {
				t.Fatal(err)
			}
			err = semantic.ResolveSymbols(ast)
			if err != nil {
				t.Fatal(err)
			}
			req := &plugin.Request{
				AST:        ast,
				OutputPath: ".",
			}
			g := newGenerator(req)
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
			if err := parseGoFile(got[0].Content + tt.goTypeDef); err != nil {
				t.Fatal(err)
			}
		})
	}
}
