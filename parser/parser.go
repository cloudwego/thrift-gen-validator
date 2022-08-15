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

func (p *Parser) Parse(st *tp.StructLike) (*Validation, map[*tp.Field]*Validation, error) {
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
			return nil, nil, fmt.Errorf("[annotation parser] parse %s's field %s failed: %w", st.Name, f.Name, err)
		}
		ret[f] = v
	}
	annotations := st.GetAnnotations()
	var validAnnotations []*tp.Annotation
	for _, anno := range annotations {
		if strings.HasPrefix(anno.Key, "vt.") {
			validAnnotations = append(validAnnotations, anno)
		}
	}
	v, err := p.parseStruct(st, validAnnotations)
	if err != nil {
		return nil, nil, fmt.Errorf("[annotation parser] parse %s's annotations failed: %w", st.Name, err)
	}
	return v, ret, nil
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
		return p.parseStructField(st, annotations)
	default:
		return nil, fmt.Errorf("type %s not recognized", typ.Name)
	}
}

func (p *Parser) parseEnum(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: EnumValidation}
	rf := NewRuleFactory(EnumKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
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
				switch nodeKey {
				case Const:
					value = &ValidationValue{
						ValueType:  BinaryValue,
						TypedValue: TypedValidationValue{Binary: annoVal},
					}
				case DefinedOnly, NotNil:
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
			exist, rule := rf.NewRule(nodeKey, value)
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
	rf := NewRuleFactory(BoolKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
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
				val, err := strconv.ParseBool(annoVal)
				if err != nil {
					return nil, fmt.Errorf("parse bool value failed: %w", err)
				}
				value = &ValidationValue{
					ValueType:  BoolValue,
					TypedValue: TypedValidationValue{Bool: val},
				}
			}
			exist, rule := rf.NewRule(nodeKey, value)
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
	rf := NewRuleFactory(NumericKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
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
				switch nodeKey {
				case Const,
					LessThan,
					LessEqual,
					GreatThan,
					GreatEqual,
					In,
					NotIn:
					val, err := strconv.ParseInt(annoVal, 0, 64)
					if err != nil {
						return nil, fmt.Errorf("parse int value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: val},
					}
				case NotNil:
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
			exist, rule := rf.NewRule(nodeKey, value)
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
	rf := NewRuleFactory(NumericKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
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
				switch nodeKey {
				case Const,
					LessThan,
					LessEqual,
					GreatThan,
					GreatEqual,
					In,
					NotIn:
					val, err := strconv.ParseFloat(annoVal, 64)
					if err != nil {
						return nil, fmt.Errorf("parse double value failed: %w", err)
					}
					value = &ValidationValue{
						ValueType:  DoubleValue,
						TypedValue: TypedValidationValue{Double: val},
					}
				case NotNil:
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
			exist, rule := rf.NewRule(nodeKey, value)
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
	rf := NewRuleFactory(BinaryKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
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
				switch nodeKey {
				case Const,
					Pattern,
					Prefix,
					Suffix,
					Contains,
					NotContains,
					In,
					NotIn:
					value = &ValidationValue{
						ValueType:  BinaryValue,
						TypedValue: TypedValidationValue{Binary: annoVal},
					}
				case MinSize,
					MaxSize:
					len, err := strconv.ParseInt(annoVal, 0, 64)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: len},
					}
				case NotNil:
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
			exist, rule := rf.NewRule(nodeKey, value)
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
	rf := NewRuleFactory(ListKeys)
	var elemAnnotations []*tp.Annotation
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
		}
		if nodeKey == Elem {
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
				switch nodeKey {
				case MinSize,
					MaxSize:
					len, err := strconv.ParseInt(annoVal, 0, 64)
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
			exist, rule := rf.NewRule(nodeKey, value)
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
			Key:   Elem,
			Inner: elemValidation,
		})
	}
	return validation, nil
}

func (p *Parser) parseMap(st *tp.StructLike, keyType, valType *tp.Type, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: MapValidation}
	rf := NewRuleFactory(MapKeys)
	var keyAnnotations []*tp.Annotation
	var valAnnotations []*tp.Annotation
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
		}
		if nodeKey == MapKey {
			elemKey := kp.toElemKey()
			keyAnnotations = append(keyAnnotations, &tp.Annotation{Key: elemKey, Values: annoVals})
			continue
		} else if nodeKey == MapValue {
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
				switch nodeKey {
				case MinSize, MaxSize:
					len, err := strconv.ParseInt(annoVal, 0, 64)
					if err != nil {
						return nil, err
					}
					value = &ValidationValue{
						ValueType:  IntValue,
						TypedValue: TypedValidationValue{Int: len},
					}
				case NoSparse:
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
			exist, rule := rf.NewRule(nodeKey, value)
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
			Key:   MapKey,
			Inner: keyValidation,
		})
	}
	if len(valAnnotations) > 0 {
		valValidation, err := p.parseField(st, valType, valAnnotations)
		if err != nil {
			return nil, fmt.Errorf("parse value annotation failed: %w", err)
		}
		validation.Rules = append(validation.Rules, &Rule{
			Key:   MapValue,
			Inner: valValidation,
		})
	}
	return validation, nil
}

func (p *Parser) parseStructField(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: StructLikeFieldValidation}
	rf := NewRuleFactory(StructLikeFieldKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
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
				val, err := strconv.ParseBool(annoVal)
				if err != nil {
					return nil, fmt.Errorf("parse struct-like value failed: %w", err)
				}
				value = &ValidationValue{
					ValueType:  BoolValue,
					TypedValue: TypedValidationValue{Bool: val},
				}
			}
			exist, rule := rf.NewRule(nodeKey, value)
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

func (p *Parser) parseStruct(st *tp.StructLike, annotations []*tp.Annotation) (*Validation, error) {
	validation := &Validation{ValidationType: StructLikeValidation}
	rf := NewRuleFactory(StructLikeKeys)
	for _, anno := range annotations {
		annoKey, annoVals := anno.Key, anno.Values
		kp, err := newKeyReader(annoKey)
		if err != nil {
			return nil, err
		}
		nodeStr := kp.next()
		nodeKey, ok := KeyFromString(nodeStr)
		if !ok {
			return nil, fmt.Errorf("invalid key %s", nodeStr)
		}
		for _, annoVal := range annoVals {
			value, err := getFunctionValidation(st, annoVal)
			if err != nil {
				p.cu.Warn(fmt.Errorf("%s parse as a function failed: %w", annoVal, err))
			}
			exist, rule := rf.NewRule(nodeKey, value)
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
