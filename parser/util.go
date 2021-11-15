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

package parser

import (
	"fmt"
	"strconv"
	"strings"

	tp "github.com/cloudwego/thriftgo/parser"
)

func (p *Function) pegText(node *node32) string {
	for n := node; n != nil; n = n.next {
		if s := p.pegText(n.up); s != "" {
			return s
		}
		if n.pegRule != rulePegText {
			continue
		}
		text := string(p.buffer[int(n.begin):int(n.end)])
		if text != "" {
			return text
		}
	}
	return ""
}

func getFieldReferenceValidation(st *tp.StructLike, anno string) (*ValidationValue, error) {
	if !strings.HasPrefix(anno, "$") {
		return nil, nil
	}
	f := getFieldReference(anno, st)
	if f == nil {
		return nil, fmt.Errorf("filed reference %s not found", anno)
	}
	return &ValidationValue{
		ValueType:  FieldReferenceValue,
		TypedValue: TypedValidationValue{FieldReference: f},
	}, nil
}

func getFieldReference(anno string, st *tp.StructLike) *tp.Field {
	name := strings.TrimPrefix(anno, "$")
	f, _ := st.GetField(name)
	return f
}

func getFunctionValidation(st *tp.StructLike, anno string) (*ValidationValue, error) {
	if !strings.HasPrefix(anno, "@") {
		return nil, nil
	}
	f, err := parseFunction(anno, st)
	if err != nil {
		return nil, err
	}
	node := f.AST().up
	// '@' Identifier LPAR Arguments RPAR
	name := f.pegText(node)
	node = node.next
	node = node.next // skip LPAR
	node = node.up   // Arguments
	arguments, err := parseFunctionArguments(st, f, node)
	if err != nil {
		return nil, err
	}
	return &ValidationValue{
		ValueType: FunctionValue,
		TypedValue: TypedValidationValue{Function: &ToolFunction{
			Name:      name,
			Arguments: arguments,
		}},
	}, nil
}

func parseFunction(anno string, st *tp.StructLike) (*Function, error) {
	f := &Function{
		Buffer: anno,
	}
	f.Init()
	if err := f.Parse(); err != nil {
		return nil, err
	}
	return f, nil
}

func parseFunctionArguments(st *tp.StructLike, p *Function, node *node32) ([]ValidationValue, error) {
	// (ConstValue ListSeparator?)*
	var ret []ValidationValue
	for ; node != nil; node = node.next {
		switch node.pegRule {
		case ruleListSeparator:
			continue
		case ruleConstValue:
			node := node.up
			switch node.pegRule {
			case ruleDoubleConstant:
				value, err := strconv.ParseFloat(p.pegText(node), 64)
				if err != nil {
					return nil, err
				}
				ret = append(ret, ValidationValue{
					ValueType: DoubleValue,
					TypedValue: TypedValidationValue{
						Double: value,
					},
				})
			case ruleIntConstant:
				value, err := strconv.ParseInt(p.pegText(node), 0, 64)
				if err != nil {
					return nil, err
				}
				ret = append(ret, ValidationValue{
					ValueType: IntValue,
					TypedValue: TypedValidationValue{
						Int: value,
					},
				})
			case ruleLiteral:
				ret = append(ret, ValidationValue{
					ValueType: BinaryValue,
					TypedValue: TypedValidationValue{
						Binary: p.pegText(node),
					},
				})
			case ruleConstList:
				// TODO: support list argument
			case ruleConstMap:
				// TODO: support map argument
			case ruleFieldReference:
				val, err := getFieldReferenceValidation(st, "$"+p.pegText(node))
				if err != nil {
					return nil, err
				}
				if val != nil {
					ret = append(ret, *val)
				}
			}
		}
	}
	return ret, nil
}
