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
)

type Key int

const (
	Const Key = iota
	LessThan
	LessEqual
	GreatThan
	GreatEqual
	In
	NotIn
	NotNil
	MinSize
	MaxSize
	Pattern
	Prefix
	Suffix
	Contains
	NotContains
	DefinedOnly
	Elem
	MapKey
	MapValue
	NoSparse
	Skip
	Assert
	_max_key
	MinRuneSize
	MaxRuneSize
)

var KeyString = [...]string{
	Const:       "const",
	LessThan:    "lt",
	LessEqual:   "le",
	GreatThan:   "gt",
	GreatEqual:  "ge",
	In:          "in",
	NotIn:       "not_in",
	NotNil:      "not_nil",
	MinSize:     "min_size",
	MaxSize:     "max_size",
	Pattern:     "pattern",
	Prefix:      "prefix",
	Suffix:      "suffix",
	Contains:    "contains",
	NotContains: "not_contains",
	DefinedOnly: "defined_only",
	Elem:        "elem",
	MapKey:      "key",
	MapValue:    "value",
	NoSparse:    "no_sparse",
	Skip:        "skip",
	Assert:      "assert",
	MaxRuneSize: "max_rune_size",
	MinRuneSize: "min_rune_size",
}

func (k Key) String() (string, bool) {
	if int(k) > len(KeyString) {
		return "", false
	}
	return KeyString[int(k)], true
}

func KeyFromString(str string) (Key, bool) {
	for key, keyStr := range KeyString {
		if str == keyStr {
			return Key(key), true
		}
	}
	return 0, false
}

var (
	RangeKeys = []Key{
		In,
		NotIn,
	}
	NumericKeys = []Key{
		Const,
		LessThan,
		LessEqual,
		GreatThan,
		GreatEqual,
		In,
		NotIn,
		NotNil,
	}
	BinaryKeys = []Key{
		Const,
		MinSize,
		MaxSize,
		Pattern,
		Prefix,
		Suffix,
		Contains,
		NotContains,
		In,
		NotIn,
		NotNil,
		MinRuneSize,
		MaxRuneSize,
	}
	BoolKeys = []Key{
		Const,
		NotNil,
	}
	EnumKeys = []Key{
		Const,
		DefinedOnly,
		NotNil,
		In,
		NotIn,
	}
	ListKeys = []Key{
		MinSize,
		MaxSize,
		Elem,
	}
	MapKeys = []Key{
		MinSize,
		MaxSize,
		NoSparse,
		MapKey,
		MapValue,
		MinRuneSize,
		MaxRuneSize,
	}
	StructLikeFieldKeys = []Key{
		Skip,
		NotNil,
	}
	StructLikeKeys = []Key{
		Assert,
	}
)

func isRangeKey(key Key) bool {
	for _, rk := range RangeKeys {
		if key == rk {
			return true
		}
	}
	return false
}

func PickSpecifiedKeys(keys []Key) (ret []Key) {
	for _, key := range keys {
		if !isRangeKey(key) {
			ret = append(ret, key)
		}
	}
	return
}

func PickRangeKeys(keys []Key) (ret []Key) {
	for _, key := range keys {
		if isRangeKey(key) {
			ret = append(ret, key)
		}
	}
	return
}

type keyParser struct {
	nodes []string
}

func newKeyReader(anno string) (*keyParser, error) {
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
