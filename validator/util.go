// Copyright 2021 Simon Wang
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

	"github.com/cloudwego/thriftgo/parser"
)

func getEnum(ast *parser.Thrift, name string) (enum *parser.Enum, includeIndex int32) {
	c, exist := ast.Name2Category[name]
	if !exist {
		return nil, -1
	}
	if c == parser.Category_Enum {
		x, ok := ast.GetEnum(name)
		if !ok {
			panic(fmt.Errorf("expect %q to be an enum in %q, not found", name, ast.Filename))
		}
		return x, -1
	}
	if c == parser.Category_Typedef {
		if x, ok := ast.GetTypedef(name); !ok {
			panic(fmt.Errorf("expect %q to be an typedef in %q, not found", name, ast.Filename))
		} else {
			if r := x.Type.Reference; r != nil {
				e, _ := getEnum(ast.Includes[r.Index].Reference, r.Name)
				if e != nil {
					return e, r.Index
				}
			}
			return getEnum(ast, x.Type.Name)
		}
	}
	return nil, -1
}
