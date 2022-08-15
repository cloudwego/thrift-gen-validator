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

	"github.com/cloudwego/thrift-gen-validator/parser"
	"github.com/cloudwego/thriftgo/generator/golang"
	tp "github.com/cloudwego/thriftgo/parser"
)

type ValidateContext struct {
	AST          *tp.Thrift
	FieldName    string
	RawFieldName string
	Resolver     *golang.Resolver
	StructLike   *golang.StructLike
	*golang.ReadWriteContext
	*parser.Validation
	IsOptional bool
	ids        map[string]int
}

func (v *ValidateContext) GenID(prefix string) (name string) {
	name = prefix
	if id := v.ids[prefix]; id > 0 {
		name += fmt.Sprint(id)
	}
	v.ids[prefix]++
	return
}

func mkStructLikeContext(utils *golang.CodeUtils, ast *tp.Thrift, resolver *golang.Resolver, st *golang.StructLike) ([]*ValidateContext, error) {
	var ret []*ValidateContext
	p := parser.NewParser(utils)
	structLikeValidation, fieldValidations, err := p.Parse(st.StructLike)
	if err != nil {
		return nil, err
	}
	ids := map[string]int{}
	for _, f := range st.Fields() {
		rwctx, err := utils.MkRWCtx(utils.RootScope(), f)
		if err != nil {
			return nil, err
		}
		ret = append(ret, &ValidateContext{
			AST:              ast,
			Resolver:         resolver,
			FieldName:        f.GoName().String(),
			RawFieldName:     f.Field.Name,
			StructLike:       st,
			ReadWriteContext: rwctx,
			Validation:       fieldValidations[f.Field],
			IsOptional:       f.Requiredness.IsOptional(),
			ids:              ids,
		})
	}
	ret = append(ret, &ValidateContext{
		AST:        ast,
		Resolver:   resolver,
		StructLike: st,
		Validation: structLikeValidation,
		ids:        ids,
	})
	return ret, nil
}
