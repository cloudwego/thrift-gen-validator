// Copyright 2021 CloudWeGo authors. 
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
// 

package parser

import (
	tp "code.byted.org/thriftgo/thriftgo/parser"
)

type ValidationType int

const (
	NumericValidation ValidationType = iota
	BinaryValidation
	BoolValidation
	EnumValidation
	ListValidation
	MapValidation
	StructLikeValidation
)

type Validation struct {
	ValidationType ValidationType
	Rules          []*Rule
}

type ValueType int

const (
	FieldReferenceValue ValueType = iota
	DoubleValue
	IntValue
	BoolValue
	EnumValue
	BinaryValue
	FunctionValue
)

type ValidationValue struct {
	ValueType  ValueType
	TypedValue TypedValidationValue
}

type TypedValidationValue struct {
	FieldReference *tp.Field
	Double         float64
	Int            int64
	Bool           bool
	Enum           *tp.EnumValue
	Binary         string
	Function       *ToolFunction
}

type Rule struct {
	Annotation string
	Specified  *ValidationValue
	Range      []*ValidationValue
	Inner      *Validation
}

type ToolFunction struct {
	Name      string
	Arguments []ValidationValue
}

type RuleFactory struct {
	specifiedKeys []string
	rangeKeys     []string
	rangeRules    []*Rule
}

func NewRuleFactory(specifiedKeys, rangeKeys []string) *RuleFactory {
	rangeRules := make([]*Rule, len(rangeKeys))
	return &RuleFactory{
		specifiedKeys: specifiedKeys,
		rangeKeys:     rangeKeys,
		rangeRules:    rangeRules,
	}
}

func (v *RuleFactory) NewRule(key string, value *ValidationValue) (bool, *Rule) {
	for _, sk := range v.specifiedKeys {
		if sk == key {
			return true, &Rule{
				Annotation: key,
				Specified:  value,
			}
		}
	}
	for i, rk := range v.rangeKeys {
		if rk == key {
			if v.rangeRules[i] == nil {
				v.rangeRules[i] = &Rule{
					Annotation: key,
					Range:      []*ValidationValue{value},
				}
				return true, v.rangeRules[i]
			} else {
				v.rangeRules[i].Range = append(v.rangeRules[i].Range, value)
				return true, nil
			}
		}
	}
	return false, nil
}
