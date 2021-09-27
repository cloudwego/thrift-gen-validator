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
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/cloudwego/thrift-gen-validator/parser"
	"github.com/cloudwego/thriftgo/generator/backend"
	"github.com/cloudwego/thriftgo/generator/golang"
	tp "github.com/cloudwego/thriftgo/parser"
	"github.com/cloudwego/thriftgo/plugin"
	"github.com/cloudwego/thriftgo/semantic"
)

var Version string

type generator struct {
	*bytes.Buffer
	*plugin.Request
	utils     *golang.CodeUtils
	warnings  []string
	indentNum int
}

func newGenerator(req *plugin.Request) *generator {
	g := &generator{
		Buffer:  &bytes.Buffer{},
		Request: req,
	}
	lf := backend.LogFunc{
		Info: func(v ...interface{}) {},
		Warn: func(v ...interface{}) {
			g.warnings = append(g.warnings, fmt.Sprint(v...))
		},
		MultiWarn: func(warns []string) {
			g.warnings = append(g.warnings, warns...)
		},
	}
	g.utils = golang.NewCodeUtils(lf)
	g.utils.HandleOptions(req.GeneratorParameters)
	return g
}

func (g *generator) writeLine(str string) {
	for i := 0; i < g.indentNum; i++ {
		g.WriteString("\t")
	}
	g.WriteString(str + "\n")
}

func (g *generator) writeLinef(format string, args ...interface{}) {
	for i := 0; i < g.indentNum; i++ {
		g.WriteString("\t")
	}
	g.WriteString(fmt.Sprintf(format, args...))
}

func (g *generator) indent() {
	g.indentNum++
}

func (g *generator) unindent() {
	g.indentNum--
}

func (g *generator) mkValidateContexts(ast *tp.Thrift, resolver *golang.Resolver, st *golang.StructLike) ([]*ValidateContext, error) {
	var ret []*ValidateContext
	p := parser.NewParser(g.utils)
	vs, err := p.Parse(st.StructLike)
	if err != nil {
		return nil, err
	}
	ids := map[string]int{}
	for _, f := range st.Fields() {
		rwctx, err := g.utils.MkRWCtx(g.utils.RootScope(), f)
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
			Validation:       vs[f.Field],
			IsOptional:       f.Requiredness.IsOptional(),
			ids:              ids,
		})
	}
	return ret, nil
}

func (g *generator) generate() ([]*plugin.Generated, error) {
	var ret []*plugin.Generated
	// generate file header
	for ast := range g.Request.AST.DepthFirstSearch() {
		g.Buffer.Reset()
		scope, err := golang.BuildScope(g.utils, ast)
		if err != nil {
			return nil, err
		}
		g.utils.SetRootScope(scope)
		t := template.New("file")
		tl, err := t.Parse(file)
		if err != nil {
			return nil, err
		}
		tl.Execute(g.Buffer, &struct {
			Version string
			PkgName string
		}{
			Version: Version,
			PkgName: g.utils.NamespaceToPackage(ast.GetNamespaceOrReferenceName("go")),
		})
		resolver := golang.NewResolver(g.utils.RootScope(), g.utils)
		// generate validation
		if err := g.generateValidation(ast, resolver); err != nil {
			return nil, err
		}
		fp := g.utils.GetFilePath(ast)
		fp = strings.TrimSuffix(fp, ".go")
		fp += "_validator.go"
		full := filepath.Join(g.Request.OutputPath, fp)
		ret = append(ret, &plugin.Generated{
			Content: g.Buffer.String(),
			Name:    &full,
		})
	}
	return ret, nil
}

func (g *generator) generateValidation(ast *tp.Thrift, resolver *golang.Resolver) error {
	scope, err := golang.BuildScope(g.utils, ast)
	if err != nil {
		return err
	}
	for _, st := range scope.StructLikes() {
		vcs, err := g.mkValidateContexts(ast, resolver, st)
		if err != nil {
			return err
		}
		g.writeLinef("func (p *%s) IsValid() error {\n", st.GoName().String())
		g.indent()
		for _, vc := range vcs {
			isStructLike := vc.Type.Category.IsStructLike()
			if len(vc.Rules) == 0 && !isStructLike {
				continue
			}

			err = g.generateFieldValidation(vc)
			if err != nil {
				return err
			}
		}
		g.writeLine("return nil")
		g.unindent()
		g.writeLine("}")
	}
	return nil
}

func (g *generator) generateFieldValidation(vc *ValidateContext) error {
	// pointer guard
	var hasNilCheck bool
	for _, r := range vc.Rules {
		if r.Annotation == parser.NotNil && r.Specified.TypedValue.Bool {
			hasNilCheck = true
			g.writeLinef("if %s == nil {\n", vc.Target)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_nil rule failed\")\n")
			g.unindent()
			g.writeLine("}")
		}
	}
	needPointerGuard := vc.IsPointer && !hasNilCheck
	if needPointerGuard {
		g.writeLinef("if %s != nil {\n", vc.Target)
		g.indent()
	}

	var err error
	if ok := vc.Type.Category.IsStructLike(); ok {
		err = g.generateStructLikeValidation(vc)
	} else if ok := vc.Type.Category.IsEnum(); ok {
		err = g.generateEnumValidation(vc)
	} else if ok := vc.Type.Category.IsBaseType(); ok {
		err = g.generateBaseTypeValidation(vc)
	} else {
		err = g.generateContainerValidation(vc)
	}
	if err != nil {
		return err
	}

	if needPointerGuard {
		g.unindent()
		g.writeLine("}")
	}
	return nil
}

func (g *generator) generateStructLikeValidation(vc *ValidateContext) error {
	var skip bool
	for _, rule := range vc.Rules {
		switch rule.Annotation {
		case parser.StructLikeAnnotation.Skip:
			if rule.Specified.TypedValue.Bool {
				g.writeLinef("// skip field %s check\n", vc.FieldName)
				skip = true
			}
		case parser.StructLikeAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown struct like annotation")
		}
	}
	if !skip {
		g.writeLinef("if err := %s.IsValid(); err != nil {\n", vc.Target)
		g.indent()
		g.writeLinef("return fmt.Errorf(\"filed %s not valid, %%w\", err)", vc.FieldName)
		g.unindent()
		g.writeLine("}")
	}
	return nil
}

func (g *generator) generateEnumValidation(vc *ValidateContext) error {
	var target, source string
	for _, rule := range vc.Rules {
		// construct target
		target = vc.Target
		if vc.IsPointer && rule.Annotation != parser.BoolAnnotation.NotNil {
			target = "*" + target
		}
		// construct source
		switch rule.Annotation {
		case parser.EnumAnnotation.Const:
			identifier := rule.Specified.TypedValue.Binary
			sss := semantic.SplitValue(identifier)
			var ref []*tp.ConstValueExtra
			for _, ss := range sss {
				switch len(ss) {
				case 2: // enum.value or someinclude.constant
					// TODO: if enum.value is written in typedef.value?

					// enum.value
					if enum, idx := getEnum(vc.AST, ss[0]); enum != nil {
						for _, v := range enum.Values {
							if v.Name == ss[1] {
								ref = append(ref, &tp.ConstValueExtra{
									IsEnum: true, Index: idx, Name: ss[1], Sel: ss[0],
								})
							}
						}
					}
					for idx, inc := range vc.AST.Includes {
						if semantic.IDLPrefix(inc.Path) != ss[0] {
							continue
						}
						if c, exist := inc.Reference.Name2Category[ss[1]]; exist {
							if c == tp.Category_Constant {
								ref = append(ref, &tp.ConstValueExtra{
									IsEnum: false, Index: int32(idx), Name: ss[1], Sel: ss[0],
								})
							}
						}
					}
				case 3: // someinclude.enum.value
					for idx, inc := range vc.AST.Includes {
						if semantic.IDLPrefix(inc.Path) != ss[0] {
							continue
						}
						if enum, _ := getEnum(inc.Reference, ss[1]); enum != nil {
							for _, v := range enum.Values {
								if v.Name == ss[2] {
									ref = append(ref, &tp.ConstValueExtra{
										IsEnum: true, Index: int32(idx), Name: ss[2], Sel: ss[1],
									})
								}
							}
						}
					}
				}
			}
			if len(ref) == 0 {
				return fmt.Errorf("undefined value: %q", identifier)
			}
			if len(ref) >= 2 {
				return fmt.Errorf("ambiguous const value %q (%d possible explainations)", identifier, len(ref))
			}
			cv := &tp.ConstValue{
				Type: tp.ConstType_ConstIdentifier,
				TypedValue: &tp.ConstTypedValue{
					Identifier: &identifier,
				},
				Extra: ref[0],
			}
			str, err := vc.Resolver.GetConstInit(vc.RawFieldName, vc.Type, cv)
			if err != nil {
				return err
			}
			source = vc.GenID("_src")
			g.writeLinef("%s := %s\n", source, str)
		case parser.EnumAnnotation.DefinedOnly,
			parser.EnumAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown bool annotation")
		}
		// generate validation code
		switch rule.Annotation {
		case parser.EnumAnnotation.Const:
			g.writeLinef("if %s != %s {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s const rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.EnumAnnotation.DefinedOnly:
			if rule.Specified.TypedValue.Bool {
				g.writeLinef("if %s.String() == \"<UNSET>\" {\n", vc.Target)
				g.indent()
				g.writeLinef("return fmt.Errorf(\"field %s defined_only rule failed\")\n", vc.FieldName)
				g.unindent()
				g.writeLine("}")
			}
		case parser.EnumAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown bool annotation")
		}
	}
	return nil
}

func (g *generator) generateBaseTypeValidation(vc *ValidateContext) error {
	switch vc.TypeID {
	case "Bool":
		return g.generateBoolValidation(vc)
	case "Byte", "I16", "I32", "I64", "Double":
		return g.generateNumericValidation(vc)
	case "String", "Binary":
		return g.generateBinaryValidation(vc)
	default:
		return errors.New("unknown base annotation")
	}
}

func (g *generator) generateBoolValidation(vc *ValidateContext) error {
	var target, source string
	for _, rule := range vc.Rules {
		// construct target
		target = vc.Target
		if vc.IsPointer && rule.Annotation != parser.BoolAnnotation.NotNil {
			target = "*" + target
		}
		// construct source
		switch rule.Annotation {
		case parser.BoolAnnotation.Const:
			vt := rule.Specified
			if vt.ValueType == parser.BoolValue {
				source = strconv.FormatBool(vt.TypedValue.Bool)
			} else if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			}
		case parser.BoolAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown bool annotation")
		}
		// generate validation code
		switch rule.Annotation {
		case parser.BoolAnnotation.Const:
			g.writeLinef("if %s != %s {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s const rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BoolAnnotation.NotNil:
			// nothing
		default:
			return errors.New("unknown bool annotation")
		}
	}
	return nil
}

func (g *generator) generateNumericValidation(vc *ValidateContext) error {
	var target, source, typeName string
	for _, rule := range vc.Rules {
		// construct target
		target = vc.Target
		typeName = vc.ReadWriteContext.TypeName.String()
		if vc.IsPointer && rule.Annotation != parser.NumericAnnotation.NotNil {
			target = "*" + target
			typeName = vc.ReadWriteContext.TypeName.Deref().String()
		}
		// construct source
		switch rule.Annotation {
		case parser.NumericAnnotation.Const, parser.NumericAnnotation.LessThan, parser.NumericAnnotation.LessEqual, parser.NumericAnnotation.GreatThan, parser.NumericAnnotation.GreatEqual:
			vt := rule.Specified
			if vt.ValueType == parser.IntValue {
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			} else if vt.ValueType == parser.DoubleValue {
				source = strconv.FormatFloat(vt.TypedValue.Double, 'f', -1, 64)
			} else if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else if vt.ValueType == parser.FunctionValue {
				source = vc.GenID("_src")
				g.writeLinef("%s := ", source)
				if err := g.generateFunction(vc.StructLike, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.NumericAnnotation.In, parser.NumericAnnotation.NotIn:
			source = vc.GenID("_src")
			g.generateSlice(vc.StructLike, source, vc.TypeID, rule.Range)
		case parser.NumericAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown numeric annotation")
		}

		switch rule.Annotation {
		case parser.NumericAnnotation.Const:
			g.writeLinef("if %s != %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not match const value, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.LessThan:
			g.writeLinef("if %s >= %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s lt rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.LessEqual:
			g.writeLinef("if %s > %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s le rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.GreatThan:
			g.writeLinef("if %s <= %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s gt rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.GreatEqual:
			g.writeLinef("if %s < %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s ge rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.In:
			exist := vc.GenID("_exist")
			g.writeLinef("var %s bool\n", exist)
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			g.writeLinef("if %s == %s(src) {\n", target, typeName)
			g.indent()
			g.writeLinef("%s = true\n", exist)
			g.writeLine("break")
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
			g.writeLinef("if !%s {\n", exist)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s in rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.NotIn:
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			g.writeLinef("if %s == %s(src) {\n", target, typeName)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_in rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
		case parser.NumericAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown numeric annotation")
		}
	}
	return nil
}

func (g *generator) generateBinaryValidation(vc *ValidateContext) error {
	var target, source string
	for _, rule := range vc.Rules {
		// construct target
		target = vc.Target
		if vc.IsPointer && rule.Annotation != parser.BinaryAnnotation.NotNil {
			target = "*" + target
		}
		// construct source
		switch rule.Annotation {
		case parser.BinaryAnnotation.Const, parser.BinaryAnnotation.Prefix, parser.BinaryAnnotation.Suffix, parser.BinaryAnnotation.Contains, parser.BinaryAnnotation.NotContains, parser.BinaryAnnotation.Pattern:
			vt := rule.Specified
			if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else if vt.ValueType == parser.FunctionValue {
				source = vc.GenID("_src")
				g.writeLinef("%s := ", source)
				if err := g.generateFunction(vc.StructLike, vt.TypedValue.Function); err != nil {
					return err
				}
			} else {
				source = vc.GenID("_src")
				if vc.TypeID == "String" || rule.Annotation == parser.BinaryAnnotation.Pattern {
					g.writeLine(source + " := \"" + vt.TypedValue.Binary + "\"")
				} else {
					g.writeLine(source + " := []byte(\"" + vt.TypedValue.Binary + "\")")
				}
			}
		case parser.BinaryAnnotation.MinLen, parser.BinaryAnnotation.MaxLen:
			vt := rule.Specified
			if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else if vt.ValueType == parser.IntValue {
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			} else if vt.ValueType == parser.FunctionValue {
				source = vc.GenID("_src")
				g.writeLinef("%s := ", source)
				if err := g.generateFunction(vc.StructLike, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.BinaryAnnotation.In, parser.BinaryAnnotation.NotIn:
			source = vc.GenID("_src")
			g.generateSlice(vc.StructLike, source, vc.TypeID, rule.Range)
		case parser.BinaryAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown binary annotation")
		}
		// generate validation code
		switch rule.Annotation {
		case parser.BinaryAnnotation.MinLen:
			g.writeLinef("if len(%s) < int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s min_len rule failed, current value: %%d\", len(%s))\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.MaxLen:
			g.writeLinef("if len(%s) > int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s max_len rule failed, current value: %%d\", len(%s))\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.Const:
			if vc.TypeID == "String" {
				g.writeLinef("if %s != %s {\n", target, source)
			} else {
				g.writeLinef("if !bytes.Equal(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not match const value, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.Prefix:
			if vc.TypeID == "String" {
				g.writeLinef("if !strings.HasPrefix(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if !bytes.HasPrefix(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s prefix rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.Suffix:
			if vc.TypeID == "String" {
				g.writeLinef("if !strings.HasSuffix(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if !bytes.HasSuffix(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s suffix rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.Contains:
			if vc.TypeID == "String" {
				g.writeLinef("if !strings.Contains(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if !bytes.Contains(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s contains rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.NotContains:
			if vc.TypeID == "String" {
				g.writeLinef("if strings.Contains(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if bytes.Contains(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_contains rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.Pattern:
			if vc.TypeID == "String" {
				g.writeLinef("if ok, _ := regexp.MatchString(%s, %s); !ok {\n", source, target)
			} else {
				g.writeLinef("if ok, _ := regexp.Match(string(%s), %s); !ok {\n", source, target)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s pattern rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.In:
			exist := vc.GenID("_exist")
			g.writeLinef("var %s bool\n", exist)
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			if vc.TypeID == "String" {
				g.writeLinef("if %s == src {\n", target)
			} else {
				g.writeLinef("if bytes.Equal(%s, src) {\n", target)
			}
			g.indent()
			g.writeLinef("%s = true\n", exist)
			g.writeLine("break")
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
			g.writeLinef("if !%s {\n", exist)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s in rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.NotIn:
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			if vc.TypeID == "String" {
				g.writeLinef("if %s == src {\n", target)
			} else {
				g.writeLinef("if bytes.Equal(%s, src) {\n", target)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_in rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
		case parser.BinaryAnnotation.NotNil:
			// do nothing
		default:
			return errors.New("unknown binary annotation")
		}
	}
	return nil
}

func (g *generator) generateContainerValidation(vc *ValidateContext) error {
	if vc.TypeID == "List" || vc.TypeID == "Set" {
		return g.generateListValidation(vc)
	}
	return g.generateMapValidation(vc)
}

func (g *generator) generateListValidation(vc *ValidateContext) error {
	var target, source string
	target = vc.Target
	if vc.IsPointer {
		target = "*" + target
	}
	for _, rule := range vc.Rules {
		switch rule.Annotation {
		case parser.ListAnnotation.MinLen, parser.ListAnnotation.MaxLen:
			vt := rule.Specified
			if vt.ValueType == parser.IntValue {
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			} else if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else if vt.ValueType == parser.FunctionValue {
				source = vc.GenID("_src")
				g.writeLinef("%s := ", source)
				if err := g.generateFunction(vc.StructLike, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.ListAnnotation.Elem:
			// do nothing
		default:
			return errors.New("unknown list annotation")
		}
		switch rule.Annotation {
		case parser.ListAnnotation.MinLen:
			g.writeLinef("if len(%s) < int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s MinLen rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.ListAnnotation.MaxLen:
			g.writeLinef("if len(%s) > int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s MaxLen rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.ListAnnotation.Elem:
			g.writeLinef("for i := 0; i < len(%s); i++ {\n", target)
			g.indent()
			elemName := vc.GenID("_elem")
			g.writeLinef("%s := %s[i]\n", elemName, target)

			vc.ValCtx.WithTarget(elemName)
			vt := &ValidateContext{
				FieldName:        elemName,
				RawFieldName:     elemName,
				Resolver:         vc.Resolver,
				ReadWriteContext: vc.ValCtx,
				StructLike:       vc.StructLike,
				Validation:       rule.Inner,
				ids:              vc.ids,
			}
			if err := g.generateFieldValidation(vt); err != nil {
				return err
			}
			g.unindent()
			g.writeLine("}")
		default:
			return errors.New("unknown list annotation")
		}
	}
	return nil
}

func (g *generator) generateMapValidation(vc *ValidateContext) error {
	var target, source string
	target = vc.Target
	if vc.IsPointer {
		target = "*" + target
	}
	for _, rule := range vc.Rules {
		switch rule.Annotation {
		case parser.MapAnnotation.MinPairs, parser.MapAnnotation.MaxPairs:
			vt := rule.Specified
			if vt.ValueType == parser.IntValue {
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			} else if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else if vt.ValueType == parser.FunctionValue {
				source = vc.GenID("_src")
				g.writeLinef("%s := ", source)
				if err := g.generateFunction(vc.StructLike, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.MapAnnotation.NoSparse:
			vt := rule.Specified
			if vt.ValueType == parser.BoolValue {
				source = strconv.FormatBool(vt.TypedValue.Bool)
			} else if vt.ValueType == parser.FieldReferenceValue {
				f := vc.StructLike.Field(vt.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			}
		case parser.MapAnnotation.Key, parser.MapAnnotation.Value:
			// do nothing
		default:
			return errors.New("unknown map annotation")
		}
		switch rule.Annotation {
		case parser.MapAnnotation.MinPairs:
			g.writeLinef("if len(%s) < int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s min_size rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.MapAnnotation.MaxPairs:
			g.writeLinef("if len(%s) > int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s max_size rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.MapAnnotation.NoSparse:
			g.writeLinef("for _, v := range %s {\n", target)
			g.indent()
			g.writeLinef("if v == nil {\n")
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s no_sparse rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
		case parser.MapAnnotation.Key:
			g.writeLinef("for k := range %s {\n", target)
			g.indent()

			vc.KeyCtx.WithTarget("k")
			vt := &ValidateContext{
				FieldName:        "k",
				RawFieldName:     "k",
				Resolver:         vc.Resolver,
				ReadWriteContext: vc.KeyCtx,
				StructLike:       vc.StructLike,
				Validation:       rule.Inner,
				ids:              vc.ids,
			}
			if err := g.generateFieldValidation(vt); err != nil {
				return err
			}
			g.unindent()
			g.writeLine("}")
		case parser.MapAnnotation.Value:
			g.writeLinef("for _, v := range %s {\n", target)
			g.indent()

			vc.ValCtx.WithTarget("v")
			vt := &ValidateContext{
				FieldName:        "v",
				RawFieldName:     "v",
				Resolver:         vc.Resolver,
				ReadWriteContext: vc.ValCtx,
				StructLike:       vc.StructLike,
				Validation:       rule.Inner,
				ids:              vc.ids,
			}
			if err := g.generateFieldValidation(vt); err != nil {
				return err
			}
			g.unindent()
			g.writeLine("}")
		default:
			return errors.New("unknown map annotation")
		}
	}
	return nil
}

func (g *generator) generateSlice(st *golang.StructLike, name, typeID string, vals []*parser.ValidationValue) error {
	if len(vals) == 0 {
		return errors.New("empty validation values")
	}
	g.writeLinef("%s := []", name)
	var vs []string
	typeid2go := map[string]string{
		"Byte":   "int8",
		"I16":    "int16",
		"I32":    "int32",
		"I64":    "int64",
		"Double": "float64",
		"String": "string",
		"Binary": "[]byte",
	}
	switch typeID {
	case "Byte",
		"I16",
		"I32",
		"I64",
		"Double",
		"String",
		"Binary":
		g.writeLinef("%s{", typeid2go[typeID])
	default:
		return fmt.Errorf("type %s not supported in generate slice", typeID)
	}
	switch typeID {
	case "Byte", "I16", "I32", "I64":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				f := st.Field(val.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else {
				source = strconv.FormatInt(val.TypedValue.Int, 10)
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	case "Double":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				f := st.Field(val.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else {
				source = strconv.FormatFloat(val.TypedValue.Double, 'f', -1, 64)
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	case "String":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				f := st.Field(val.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else {
				source = "\"" + val.TypedValue.Binary + "\""
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	case "Binary":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				f := st.Field(val.TypedValue.FieldReference.Name)
				source = "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					source = "*" + source
				}
			} else {
				source = "[]byte(\"" + val.TypedValue.Binary + "\")"
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	default:
		return fmt.Errorf("type %s not supported in generate slice", typeID)
	}
	g.writeLinef("%s}\n", strings.Join(vs, ", "))
	return nil
}

func (g *generator) generateFunction(st *golang.StructLike, f *parser.ToolFunction) error {
	switch f.Name {
	case "len":
		f := st.Field(f.Arguments[0].TypedValue.FieldReference.Name)
		reference := "p." + f.GoName().String()
		if f.GoTypeName().IsPointer() {
			reference = "*" + reference
		}
		g.writeLinef("len(%s)\n", reference)
	case "sprintf":
		g.writeLinef("fmt.Sprintf(")
		var args []string
		for _, arg := range f.Arguments {
			if arg.ValueType == parser.BinaryValue {
				args = append(args, "\""+arg.TypedValue.Binary+"\"")
			} else if arg.ValueType == parser.FieldReferenceValue {
				f := st.Field(arg.TypedValue.FieldReference.Name)
				reference := "p." + f.GoName().String()
				if f.GoTypeName().IsPointer() {
					reference = "*" + reference
				}
				args = append(args, reference)
			}
		}
		g.writeLine(strings.Join(args, ",") + ")")
	default:
		return errors.New("unknown function: " + f.Name)
	}
	return nil
}
