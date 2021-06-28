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

package main

// StructLikeValidate .
var StructLikeValidate = `
{{define "StructLikeValidate"}}
{{- $TypeName := .Name | Identify}}
func (p *{{$TypeName}}) IsValid() bool {
	{{- ctxs := MkValidateContexts .Fields}}
	{{- range .ctxs}}
	{{template "FieldValidate" .}}
	{{- end}}{{/* range .ctxs */}}
	return true
}
{{- end}}{{/* "StructLikeValidate" */}}
`

// FieldValidate .
var FieldValidate = `
{{define "FieldValidate"}}
{{- if IsStructLike .Type}}
	{{- template "FieldValidateStructLike" . -}}
{{- else if IsBaseType .Type}}
	{{- template "FieldValidateBase" . -}}
{{- else}}{{/* IsContainerType */}}
	{{- template "FieldValidateContainer" . -}}
{{- end}}
{{- end}}{{/* "FieldValidate" */}}
`

// FieldValidateStructLike .
var FieldValidateStructLike = `
{{define "FieldValidateStructLike"}}
	{{- rule := range .Rules}}
	{{- if eq .Annotation $StructLikeAnnotation.Skip}}
	
	{{- else if eq . Annotation $StructLikeAnnotation.NotNil}}
	{{- end}}
	if !{{.Target}}.IsValid({{.Source}}) {
		return false
	}
{{- end}}{{/* "FieldValidateStructLike" */}}
`

// FieldValidateBase .
var FieldValidateBase = `
{{define "FieldValidateBase"}}
	{{- if .IsPointer}}
	if {{.Target}} == {{.Source}} {
		return true
	} else if {{.Target}} == nil || {{.Source}} == nil {
		return false
	}
	{{- end}}
	{{- $tgt := .Target}}
	{{- $src := .Source}}
	{{- if .IsPointer}}{{$tgt = printf "*%s" $tgt}}{{$src = printf "*%s" $src}}{{end}}
	{{- if IsStringType .Type}}
		if strings.Compare({{$tgt}}, {{$src}}) != 0 {
			return false
		}
	{{- else if IsBinaryType .Type}}
		if bytes.Compare({{$tgt}}, {{$src}}) != 0 {
			return false
		}
	{{- else}}{{/* IsFixedLengthType */}}
		if {{$tgt}} != {{$src}} {
			return false
		}
	{{- end}}
{{- end}}{{/* "FieldValidateBase" */}}
`

// FieldValidateContainer .
var FieldValidateContainer = `
{{define "FieldValidateContainer"}}
	{{- if .IsPointer}}
	if {{.Target}} == {{.Source}} {
		return true
	} else if {{.Target}} == nil || {{.Source}} == nil {
		return false
	}
	{{- end}}
	{{- if eq "Map" .TypeID}}
		{{- template "FieldValidateMap" .}}
	{{- else if eq "List" .TypeID}}
		{{- template "FieldValidateList" .}}
	{{- else}}{{/* "Set" */}}
		{{- template "FieldValidateSet" .}}
	{{- end}}
{{- end}}{{/* "FieldValidateContainer" */}}
`

// FieldValidateList .
var FieldValidateList = `
{{define "FieldValidateList"}}
	if len({{.Target}}) != len({{.Source}}) {
		return false
	}
	{{- $src := GenID "_src"}}
	for i, v := range {{.Target}} {
		{{$src}} := {{.Source}}[i]
		{{- $ctx := MkRWCtx2 (.Type | GetValType) "v" $src false false}}
		{{- template "FieldValidate" $ctx}}
	}
{{- end}}{{/* "FieldValidateList" */}}
`

// FieldValidateSet .
var FieldValidateSet = `
{{define "FieldValidateSet"}}
	if len({{.Target}}) != len({{.Source}}) {
		return false
	}
	{{- $src := GenID "_src"}}
	for i, v := range {{.Target}} {
		{{$src}} := {{.Source}}[i]
		{{- $ctx := MkRWCtx2 (.Type | GetValType) "v" $src false false}}
		{{- template "FieldValidate" $ctx}}
	}
{{- end}}{{/* "FieldValidateSet" */}}
`

// FieldValidateMap .
var FieldValidateMap = `
{{define "FieldValidateMap"}}
	if len({{.Target}}) != len({{.Source}}) {
		return false
	}
	{{- $src := GenID "_src"}}
	for k, v := range {{.Target}}{
		{{$src}} := {{.Source}}[k]
		{{$ctx := MkRWCtx2 (.Type | GetValType) "v" $src false false}}
		{{- template "FieldValidate" $ctx}}
	}
{{- end}}{{/* "FieldValidateMap" */}}
`
