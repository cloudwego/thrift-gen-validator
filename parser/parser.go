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

	"github.com/cloudwego/thriftgo/generator/golang"
	tp "github.com/cloudwego/thriftgo/parser"
)

type Parser struct {
	cu *golang.CodeUtils
}

func NewParser(cu *golang.CodeUtils) *Parser {
	return &Parser{cu}
}

func (p *Parser) Parse(st *tp.StructLike) (map[*tp.Field]*Validation, error) {
	ret := make(map[*tp.Field]*Validation)
	for _, f := range st.GetFields() {
		annotations := f.GetAnnotations()
		var validAnnotations []*tp.Annotation
		for _, anno := range annotations {
			if strings.HasPrefix(anno.Key, "vt.") {
				validAnnotations = append(validAnnotations, anno)
			}
		}
		v, err := p.parseField(st, f.Type, validAnnotations)
		if err != nil {
			return nil, fmt.Errorf("[annotation parser] parse %s's field %s failed: %w", st.Name, f.Name, err)
		}
		ret[f] = v
	}
	return ret, nil
}

func (p *Parser) parseField(st *tp.StructLike, typ *tp.Type, annotations []*tp.Annotation) (*Validation, error) {
	if typ.Category.IsEnum() {
		return p.parseEnum(st, annotations)
	}
	switch golang.GetTypeID(typ) {
	case "Bool":
		return p.parseBool(st, annotations)
	case "Double":
		return p.parseDouble(st, annotations)
	case "Byte", "I16", "I32", "I64":
		return p.parseInt(st, annotations)
	case "String", "Binary":
		return p.parseBinary(st, annotations)
	case "Set", "List":
		return p.parseList(st, typ.ValueType, annotations)
	case "Map":
		return p.parseMap(st, typ.KeyType, typ.ValueType, annotations)
	case "Struct":
		return p.parseStruct(st, annotations)
	default:
		return nil, fmt.Errorf("type %s not recognized", golang.GetTypeID(typ))
	}
}

func (p *Parser) parseEnum(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: EnumValidation}
	specifiedKeys := []string{
		EnumAnnotation.Const,
		EnumAnnotation.DefinedOnly,
		EnumAnnotation.NotNil,
	}
	rangeKeys := []string{}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				switch node {
				case EnumAnnotation.Const:
					value = &ValidationValue{
						ValueType:  BinaryValue,
						TypedValue: TypedValidationValue{Binary: annoVal},
					}
				case EnumAnnotation.DefinedOnly, EnumAnnotation.NotNil:
					val, err := strconv.ParseBool(annoVal)
					if err != nil {
						return nil, fmt.Errorf("parse bool value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  BoolValue,
						TypedValue: TypedValidationValue{Bool: val},
					}
				default:
					return nil, fmt.Errorf("unrecognized enum annotation key %s", annoKey)
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized enum annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	return validation, nil
}

func (p *Parser) parseBool(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: BoolValidation}
	specifiedKeys := []string{
		BoolAnnotation.Const,
		BoolAnnotation.NotNil,
	}
	rangeKeys := []string{}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				val, err := strconv.ParseBool(annoVal)
				if err != nil {
					return nil, fmt.Errorf("parse bool value failed: %w", err)
				}
				value = &ValidationValue{
					ValueType:  BoolValue,
					TypedValue: TypedValidationValue{Bool: val},
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized bool annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	return validation, nil
}

func (p *Parser) parseInt(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: NumericValidation}
	specifiedKeys := []string{
		NumericAnnotation.Const,
		NumericAnnotation.LessThan,
		NumericAnnotation.LessEqual,
		NumericAnnotation.GreatThan,
		NumericAnnotation.GreatEqual,
		NumericAnnotation.NotNil,
	}
	rangeKeys := []string{
		NumericAnnotation.In,
		NumericAnnotation.NotIn,
	}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				switch node {
				case NumericAnnotation.Const,
					NumericAnnotation.LessThan,
					NumericAnnotation.LessEqual,
					NumericAnnotation.GreatThan,
					NumericAnnotation.GreatEqual,
					NumericAnnotation.In,
					NumericAnnotation.NotIn:
					val, err := strconv.ParseInt(annoVal, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("parse int value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: val},
					}
				case NumericAnnotation.NotNil:
					val, err := strconv.ParseBool(annoVal)
					if err != nil {
						return nil, fmt.Errorf("parse int value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  BoolValue,
						TypedValue: TypedValidationValue{Bool: val},
					}
				default:
					return nil, fmt.Errorf("unrecognized numeric annotation key %s", annoKey)
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized numeric annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	return validation, nil
}

func (p *Parser) parseDouble(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: NumericValidation}
	specifiedKeys := []string{
		NumericAnnotation.Const,
		NumericAnnotation.LessThan,
		NumericAnnotation.LessEqual,
		NumericAnnotation.GreatThan,
		NumericAnnotation.GreatEqual,
		NumericAnnotation.NotNil,
	}
	rangeKeys := []string{
		NumericAnnotation.In,
		NumericAnnotation.NotIn,
	}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				switch node {
				case NumericAnnotation.Const,
					NumericAnnotation.LessThan,
					NumericAnnotation.LessEqual,
					NumericAnnotation.GreatThan,
					NumericAnnotation.GreatEqual,
					NumericAnnotation.In,
					NumericAnnotation.NotIn:
					val, err := strconv.ParseFloat(annoVal, 10)
					if err != nil {
						return nil, fmt.Errorf("parse double value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  DoubleValue,
						TypedValue: TypedValidationValue{Double: val},
					}
				case NumericAnnotation.NotNil:
					val, err := strconv.ParseBool(annoVal)
					if err != nil {
						return nil, fmt.Errorf("parse int value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  BoolValue,
						TypedValue: TypedValidationValue{Bool: val},
					}
				default:
					return nil, fmt.Errorf("unrecognized numeric annotation key %s", annoKey)
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized numeric annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	return validation, nil
}

func (p *Parser) parseBinary(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: BinaryValidation}
	specifiedKeys := []string{
		BinaryAnnotation.Const,
		BinaryAnnotation.Pattern,
		BinaryAnnotation.Prefix,
		BinaryAnnotation.Suffix,
		BinaryAnnotation.Contains,
		BinaryAnnotation.NotContains,
		BinaryAnnotation.MinLen,
		BinaryAnnotation.MaxLen,
		BinaryAnnotation.NotNil,
	}
	rangeKeys := []string{
		BinaryAnnotation.In,
		BinaryAnnotation.NotIn,
	}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				switch node {
				case BinaryAnnotation.Const,
					BinaryAnnotation.Pattern,
					BinaryAnnotation.Prefix,
					BinaryAnnotation.Suffix,
					BinaryAnnotation.Contains,
					BinaryAnnotation.NotContains,
					BinaryAnnotation.In,
					BinaryAnnotation.NotIn:
					value = &ValidationValue{
						ValueType:  BinaryValue,
						TypedValue: TypedValidationValue{Binary: annoVal},
					}
				case BinaryAnnotation.MinLen,
					BinaryAnnotation.MaxLen:
					len, err := strconv.ParseInt(annoVal, 10, 64)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: len},
					}
				case BinaryAnnotation.NotNil:
					val, err := strconv.ParseBool(annoVal)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  BoolValue,
						TypedValue: TypedValidationValue{Bool: val},
					}
				default:
					return nil, fmt.Errorf("unrecognized binary annotation key %s", annoKey)
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized binary annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	return validation, nil
}

func (p *Parser) parseList(st *tp.StructLike, elemType *tp.Type, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: ListValidation}
	specifiedKeys := []string{
		ListAnnotation.MinLen,
		ListAnnotation.MaxLen,
	}
	rangeKeys := []string{}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	var elemAnnotations []*tp.Annotation
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		if node == ListAnnotation.Elem {
			elemKey := kp.toElemKey()
			elemAnnotations = append(elemAnnotations, &tp.Annotation{Key: elemKey, Values: annoVals})
			continue
		}
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				switch node {
				case ListAnnotation.MinLen,
					ListAnnotation.MaxLen:
					len, err := strconv.ParseInt(annoVal, 10, 64)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: len},
					}
				default:
					return nil, fmt.Errorf("unrecognized list annotation key %s", annoKey)
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized list annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	if len(elemAnnotations) > 0 {
		elemValidation, err := p.parseField(st, elemType, elemAnnotations)
		if err != nil {
			return nil, fmt.Errorf("parse element annotation failed: %w", err)
		}
		validation.Rules = append(validation.Rules, &Rule{
			Annotation: ListAnnotation.Elem,
			Inner:      elemValidation,
		})
	}
	return validation, nil
}

func (p *Parser) parseMap(st *tp.StructLike, keyType, valType *tp.Type, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: MapValidation}
	specifiedKeys := []string{
		MapAnnotation.MinPairs,
		MapAnnotation.MaxPairs,
		MapAnnotation.NoSparse,
	}
	rangeKeys := []string{}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	var keyAnnotations []*tp.Annotation
	var valAnnotations []*tp.Annotation
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		if node == MapAnnotation.Key {
			elemKey := kp.toElemKey()
			keyAnnotations = append(keyAnnotations, &tp.Annotation{Key: elemKey, Values: annoVals})
			continue
		} else if node == MapAnnotation.Value {
			elemKey := kp.toElemKey()
			valAnnotations = append(valAnnotations, &tp.Annotation{Key: elemKey, Values: annoVals})
			continue
		}
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				switch node {
				case MapAnnotation.MinPairs, MapAnnotation.MaxPairs:
					len, err := strconv.ParseInt(annoVal, 10, 64)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: len},
					}
				case MapAnnotation.NoSparse:
					val, err := strconv.ParseBool(annoVal)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  BoolValue,
						TypedValue: TypedValidationValue{Bool: val},
					}
				default:
					return nil, fmt.Errorf("unrecognized map annotation key %s", annoKey)
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized map annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	if len(keyAnnotations) > 0 {
		keyValidation, err := p.parseField(st, keyType, keyAnnotations)
		if err != nil {
			return nil, fmt.Errorf("parse key annotation failed: %w", err)
		}
		validation.Rules = append(validation.Rules, &Rule{
			Annotation: MapAnnotation.Key,
			Inner:      keyValidation,
		})
	}
	if len(valAnnotations) > 0 {
		valValidation, err := p.parseField(st, valType, valAnnotations)
		if err != nil {
			return nil, fmt.Errorf("parse value annotation failed: %w", err)
		}
		validation.Rules = append(validation.Rules, &Rule{
			Annotation: MapAnnotation.Value,
			Inner:      valValidation,
		})
	}
	return validation, nil
}

func (p *Parser) parseStruct(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: StructLikeValidation}
	specifiedKeys := []string{StructLikeAnnotation.NotNil, StructLikeAnnotation.Skip}
	rangeKeys := []string{}
	rf := NewRuleFactory(specifiedKeys, rangeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyParser(annoKey)
		if err != nil {
			return nil, err
		}
		node := kp.next()
		for _, annoVal := range annoVals {
			value, err := getFieldReferenceValidation(st, annoVal)
			if err != nil {
				return nil, err
			}
			if value == nil {
				value, err = getFunctionValidation(st, annoVal)
				if err != nil {
					p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
				}
			}
			if value == nil {
				val, err := strconv.ParseBool(annoVal)
				if err != nil {
					return nil, fmt.Errorf("parse struct-like value failed: %w", err)
				}
				value = &ValidationValue{
					ValueType:  IntValue,
					TypedValue: TypedValidationValue{Bool: val},
				}
			}
			exist, rule := rf.NewRule(node, value)
			if !exist {
				return nil, fmt.Errorf("unrecognized struct-like annotation key %s", annoKey)
			}
			if rule != nil {
				validation.Rules = append(validation.Rules, rule)
			}
		}
	}
	return validation, nil
}
