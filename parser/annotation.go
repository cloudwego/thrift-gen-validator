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
	"errors"
	"strings"
)

const (
	validatorPrefix = "vt"
	NotNil          = "not_nil"
)

var (
	NumericAnnotation = struct {
		Const      string
		LessThan   string
		LessEqual  string
		GreatThan  string
		GreatEqual string
		In         string
		NotIn      string
		NotNil     string
	}{
		Const:      "const",
		LessThan:   "lt",
		LessEqual:  "le",
		GreatThan:  "gt",
		GreatEqual: "ge",
		In:         "in",
		NotIn:      "not_in",
		NotNil:     NotNil,
	}
	BinaryAnnotation = struct {
		Const       string
		MinLen      string
		MaxLen      string
		Pattern     string
		Prefix      string
		Suffix      string
		Contains    string
		NotContains string
		In          string
		NotIn       string
		NotNil      string
	}{
		Const:       "const",
		MinLen:      "min_size",
		MaxLen:      "max_size",
		Pattern:     "pattern",
		Prefix:      "prefix",
		Suffix:      "suffix",
		Contains:    "contains",
		NotContains: "not_contains",
		In:          "in",
		NotIn:       "not_in",
		NotNil:      NotNil,
	}
	BoolAnnotation = struct {
		Const  string
		NotNil string
	}{
		Const:  "const",
		NotNil: NotNil,
	}
	EnumAnnotation = struct {
		Const       string
		DefinedOnly string
		NotNil      string
	}{
		Const:       "const",
		DefinedOnly: "defined_only",
		NotNil:      NotNil,
	}
	ListAnnotation = struct {
		MinLen string
		MaxLen string
		Elem   string
	}{
		MinLen: "min_size",
		MaxLen: "max_size",
		Elem:   "elem",
	}
	MapAnnotation = struct {
		MinPairs string
		MaxPairs string
		NoSparse string
		Key      string
		Value    string
	}{
		MinPairs: "min_size",
		MaxPairs: "max_size",
		NoSparse: "no_sparse",
		Key:      "key",
		Value:    "value",
	}
	StructLikeAnnotation = struct {
		Skip   string
		NotNil string
	}{
		Skip:   "skip",
		NotNil: NotNil,
	}
)

type keyParser struct {
	nodes []string
}

func newKeyParser(anno string) (*keyParser, error) {
	nodes := strings.Split(anno, ".")
	if len(nodes) < 2 || nodes[0] != validatorPrefix {
		return nil, errors.New("invalid annotation key")
	}
	return &keyParser{nodes: nodes[1:]}, nil
}

func (k *keyParser) next() string {
	if len(k.nodes) == 0 {
		return ""
	}
	ret := k.nodes[0]
	k.nodes = k.nodes[1:]
	return ret
}

func (k *keyParser) toElemKey() string {
	ret := []string{validatorPrefix}
	ret = append(ret, k.nodes...)
	return strings.Join(ret, ".")
}
