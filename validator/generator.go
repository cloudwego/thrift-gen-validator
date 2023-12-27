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

	"github.com/cloudwego/thrift-gen-validator/config"
	"github.com/cloudwego/thrift-gen-validator/parser"
	"github.com/cloudwego/thriftgo/generator/backend"
	"github.com/cloudwego/thriftgo/generator/golang"
	tp "github.com/cloudwego/thriftgo/parser"
	"github.com/cloudwego/thriftgo/plugin"
	"github.com/cloudwego/thriftgo/semantic"
)

var Version string

var ValidMethodName string = "IsValid"

type generator struct {
	config     *config.Config
	request    *plugin.Request
	utils      *golang.CodeUtils
	buffer     *bytes.Buffer
	indentNum  int
	warnings   []string
	usedFuncs  map[*template.Template]bool
	enumImport []string
}

func newGenerator(req *plugin.Request) (*generator, error) {
	var cfg config.Config
	if err := cfg.Unpack(req.PluginParameters); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plugin parameters: %v", err)
	}
	g := &generator{
		buffer:    &bytes.Buffer{},
		config:    &cfg,
		request:   req,
		usedFuncs: make(map[*template.Template]bool),
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
	if parseExtend(req.PluginParameters) {
		ValidMethodName = "IsStructValid"
	}

	return g, nil
}

func parseExtend(params []string) bool {
	for _, parameter := range params {
		if strings.HasPrefix(parameter, "avoid_name") {
			return true
		}
	}
	return false
}

func (g *generator) write(str string) {
	g.buffer.WriteString(str)
}

func (g *generator) writeLine(str string) {
	for i := 0; i < g.indentNum; i++ {
		g.buffer.WriteString("\t")
	}
	g.buffer.WriteString(str + "\n")
}

func (g *generator) writeLinef(format string, args ...interface{}) {
	for i := 0; i < g.indentNum; i++ {
		g.buffer.WriteString("\t")
	}
	g.buffer.WriteString(fmt.Sprintf(format, args...))
}

func (g *generator) indent() {
	g.indentNum++
}

func (g *generator) unindent() {
	g.indentNum--
}

func (g *generator) generate() ([]*plugin.Generated, error) {
	var ret []*plugin.Generated
	// generate file header
	for ast := range g.request.AST.DepthFirstSearch() {
		g.buffer.Reset()
		g.enumImport = g.enumImport[:0]
		scope, err := golang.BuildScope(g.utils, ast)
		if err != nil {
			return nil, err
		}
		g.utils.SetRootScope(scope)
		resolver := golang.NewResolver(g.utils.RootScope(), g.utils)
		// generate validation
		if err := g.generateBody(ast, resolver); err != nil {
			return nil, err
		}
		header, err := g.renderHeader(ast)
		if err != nil {
			return nil, err
		}
		content := header + g.buffer.String()
		fp := g.utils.GetFilePath(ast)
		fp = strings.TrimSuffix(fp, ".go")
		fp += "_validator.go"
		full := filepath.Join(g.request.OutputPath, fp)
		ret = append(ret, &plugin.Generated{
			Content: content,
			Name:    &full,
		})
	}
	return ret, nil
}

func (g *generator) renderHeader(ast *tp.Thrift) (string, error) {
	var header bytes.Buffer
	t := template.New("file")
	tl, err := t.Parse(file)
	if err != nil {
		return "", err
	}

	var importBuf, importGuardBuf bytes.Buffer
	for tpl := range g.usedFuncs {
		if strings.Contains(tpl.DefinedTemplates(), "Import") {
			if err := tpl.ExecuteTemplate(&importBuf, "Import", ast); err != nil {
				g.utils.Warn(fmt.Sprintf("failed to Imports template of %s, err: %v", tpl.Name(), err))
			}
		}
		if strings.Contains(tpl.DefinedTemplates(), "ImportGuard") {
			if err = tpl.ExecuteTemplate(&importGuardBuf, "ImportGuard", ast); err != nil {
				g.utils.Warn(fmt.Sprintf("failed to ImportGuards template of %s, err: %v", tpl.Name(), err))
			}
		}
	}
	importStr := strings.TrimSpace(importBuf.String())
	importStr = strings.ReplaceAll(importStr, "\n\n", "\n")
	importGuardStr := strings.TrimSpace(importGuardBuf.String())
	importGuardStr = strings.ReplaceAll(importGuardStr, "\n\n", "\n")
	enumUnique := make(map[string]struct{}, len(g.enumImport))
	for _, impt := range g.enumImport {
		if _, exist := enumUnique[impt]; !exist {
			var importAlias string
			for _, inc := range g.utils.RootScope().Includes() {
				if inc.ImportPath == impt {
					if inc.PackageName == filepath.Base(inc.ImportPath) {
						importAlias = inc.PackageName + " "
					}
					break
				}
			}
			importStr = importStr + importAlias + "\"" + impt + "\"\n"
			enumUnique[impt] = struct{}{}
		}
	}
	tl.Execute(&header, &struct {
		Version     string
		PkgName     string
		Import      string
		ImportGuard string
	}{
		Import:      importStr,
		ImportGuard: importGuardStr,
		Version:     Version,
		PkgName:     g.utils.NamespaceToPackage(ast.GetNamespaceOrReferenceName("go")),
	})
	return header.String(), nil
}

func (g *generator) generateBody(ast *tp.Thrift, resolver *golang.Resolver) error {
	scope, err := golang.BuildScope(g.utils, ast)
	if err != nil {
		return err
	}
	for _, st := range scope.StructLikes() {
		vcs, err := mkStructLikeContext(g.utils, ast, resolver, st)
		if err != nil {
			return err
		}
		g.writeLinef("func (p *%s) "+ValidMethodName+"() error {\n", st.GoName().String())
		g.indent()
		for _, vc := range vcs {
			switch vc.ValidationType {
			case parser.StructLikeValidation:
				if len(vc.Rules) == 0 {
					continue
				}
				if err = g.generateStructLikeValidation(vc); err != nil {
					return err
				}
			default:
				isStructLike := vc.Type.Category.IsStructLike()
				if len(vc.Rules) == 0 && !isStructLike {
					continue
				}
				if err = g.generateFieldValidation(vc); err != nil {
					return err
				}
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
		if r.Key == parser.NotNil && r.Specified.TypedValue.Bool {
			hasNilCheck = true
			g.writeLinef("if %s == nil {\n", vc.Target)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_nil rule failed\")\n", vc.FieldName)
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
		err = g.generateStructLikeFieldValidation(vc)
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

func (g *generator) generateStructLikeFieldValidation(vc *ValidateContext) error {
	var skip bool
	for _, rule := range vc.Rules {
		switch rule.Key {
		case parser.Skip:
			if rule.Specified.TypedValue.Bool {
				g.writeLinef("// skip field %s check\n", vc.FieldName)
				skip = true
			}
		case parser.NotNil:
			// do nothing
		default:
			return errors.New("unknown struct like annotation")
		}
	}
	if !skip {
		g.writeLinef("if err := %s."+ValidMethodName+"(); err != nil {\n", vc.Target)
		g.indent()
		g.writeLinef("return fmt.Errorf(\"field %s not valid, %%w\", err)", vc.FieldName)
		g.unindent()
		g.writeLine("}")
	}
	return nil
}

func (g *generator) generateStructLikeValidation(vc *ValidateContext) error {
	for _, rule := range vc.Rules {
		switch rule.Key {
		case parser.Assert:
			source := vc.GenID("_assert")
			err := g.generateFunction(source, vc, rule.Specified.TypedValue.Function)
			if err != nil {
				return err
			}
			g.writeLinef("if !(" + source + ") {\n")
			g.indent()
			g.writeLine("return fmt.Errorf(\"struct assertion failed\")")
			g.unindent()
			g.writeLine("}")
		default:
			return errors.New("unknown struct like annotation")
		}
	}
	return nil
}

func (g *generator) parseEnumValue(identifier string, vc *ValidateContext) (golang.Code, error) {
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
					_, refImport := g.utils.Import(inc.GetReference())
					_, curImport := g.utils.Import(vc.AST)
					// prevent self-import
					if refImport != curImport {
						g.enumImport = append(g.enumImport, refImport)
					}
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
		return "", fmt.Errorf("undefined value: %q", identifier)
	}
	if len(ref) >= 2 {
		return "", fmt.Errorf("ambiguous const value %q (%d possible explainations)", identifier, len(ref))
	}
	cv := &tp.ConstValue{
		Type: tp.ConstType_ConstIdentifier,
		TypedValue: &tp.ConstTypedValue{
			Identifier: &identifier,
		},
		Extra: ref[0],
	}
	// todo update go.mod for bugfix for same namespace
	return vc.Resolver.GetConstInit(vc.RawFieldName, vc.Type, cv)
}

func (g *generator) generateEnumValidation(vc *ValidateContext) error {
	var target, source string
	for _, rule := range vc.Rules {
		// construct target
		target = vc.Target
		if vc.IsPointer && rule.Key != parser.NotNil {
			target = "*" + target
		}
		// construct source
		switch rule.Key {
		case parser.Const:
			identifier := rule.Specified.TypedValue.Binary
			str, err := g.parseEnumValue(identifier, vc)
			if err != nil {
				return err
			}
			source = vc.GenID("_src")
			g.writeLinef("%s := %s\n", source, str)
		case parser.In, parser.NotIn:
			source = vc.GenID("_src")
			g.generateEnumSlice(source, vc.Type.Name, rule.Range, vc)
		case parser.DefinedOnly,
			parser.NotNil:
			// do nothing
		default:
			return errors.New("unknown enum annotation")
		}
		// generate validation code
		switch rule.Key {
		case parser.Const:
			g.writeLinef("if %s != %s {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s const rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.DefinedOnly:
			if rule.Specified.TypedValue.Bool {
				g.writeLinef("if %s.String() == \"<UNSET>\" {\n", vc.Target)
				g.indent()
				g.writeLinef("return fmt.Errorf(\"field %s defined_only rule failed\")\n", vc.FieldName)
				g.unindent()
				g.writeLine("}")
			}
		case parser.NotNil:
			// do nothing
		case parser.In:
			exist := vc.GenID("_exist")
			g.writeLinef("var %s bool\n", exist)
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			g.writeLinef("if %s == src {\n", target)
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
		case parser.NotIn:
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			g.writeLinef("if %s == src {\n", target)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_in rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
		default:
			return errors.New("unknown enum annotation")
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
		if vc.IsPointer && rule.Key != parser.NotNil {
			target = "*" + target
		}
		// construct source
		switch rule.Key {
		case parser.Const:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.BoolValue:
				source = strconv.FormatBool(vt.TypedValue.Bool)
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			}
		case parser.NotNil:
			// do nothing
		default:
			return errors.New("unknown bool annotation")
		}
		// generate validation code
		switch rule.Key {
		case parser.Const:
			g.writeLinef("if %s != %s {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s const rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NotNil:
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
		typeName = vc.TypeName.String()
		if vc.IsPointer && rule.Key != parser.NotNil {
			target = "*" + target
			typeName = vc.TypeName.Deref().String()
		}
		// construct source
		switch rule.Key {
		case parser.Const, parser.LessThan, parser.LessEqual, parser.GreatThan, parser.GreatEqual:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.IntValue:
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			case parser.DoubleValue:
				source = strconv.FormatFloat(vt.TypedValue.Double, 'f', -1, 64)
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			case parser.FunctionValue:
				source = vc.GenID("_src")
				if err := g.generateFunction(source, vc, vt.TypedValue.Function); err != nil {
					return err
				}
				g.write("\n")
			default:
				return fmt.Errorf("unsupported value type for %s in numeric validation", parser.KeyString[rule.Key])
			}
		case parser.In, parser.NotIn:
			source = vc.GenID("_src")
			g.generateSlice(vc.StructLike, source, vc.TypeID, rule.Range)
		case parser.NotNil:
			// do nothing
		default:
			return errors.New("unknown numeric annotation")
		}

		switch rule.Key {
		case parser.Const:
			g.writeLinef("if %s != %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not match const value, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.LessThan:
			g.writeLinef("if %s >= %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s lt rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.LessEqual:
			g.writeLinef("if %s > %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s le rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.GreatThan:
			g.writeLinef("if %s <= %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s gt rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.GreatEqual:
			g.writeLinef("if %s < %s(%s) {\n", target, typeName, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s ge rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.In:
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
		case parser.NotIn:
			g.writeLinef("for _, src := range %s {\n", source)
			g.indent()
			g.writeLinef("if %s == %s(src) {\n", target, typeName)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_in rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
		case parser.NotNil:
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
		if vc.IsPointer && rule.Key != parser.NotNil {
			target = "*" + target
		}
		// construct source
		switch rule.Key {
		case parser.Const, parser.Prefix, parser.Suffix, parser.Contains, parser.NotContains, parser.Pattern:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			case parser.FunctionValue:
				source = vc.GenID("_src")
				if err := g.generateFunction(source, vc, vt.TypedValue.Function); err != nil {
					return err
				}
			default:
				source = vc.GenID("_src")
				if vc.TypeID == "String" || rule.Key == parser.Pattern {
					g.writeLine(source + " := \"" + vt.TypedValue.Binary + "\"")
				} else {
					g.writeLine(source + " := []byte(\"" + vt.TypedValue.Binary + "\")")
				}
			}
		case parser.MinSize, parser.MaxSize:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			case parser.IntValue:
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			case parser.FunctionValue:
				source = vc.GenID("_src")
				if err := g.generateFunction(source, vc, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.In, parser.NotIn:
			source = vc.GenID("_src")
			g.generateSlice(vc.StructLike, source, vc.TypeID, rule.Range)
		case parser.NotNil:
			// do nothing
		default:
			return errors.New("unknown binary annotation")
		}
		// generate validation code
		switch rule.Key {
		case parser.MinSize:
			g.writeLinef("if len(%s) < int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s min_len rule failed, current value: %%d\", len(%s))\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.MaxSize:
			g.writeLinef("if len(%s) > int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s max_len rule failed, current value: %%d\", len(%s))\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.Const:
			if vc.TypeID == "String" {
				g.writeLinef("if %s != %s {\n", target, source)
			} else {
				g.writeLinef("if !bytes.Equal(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not match const value, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.Prefix:
			if vc.TypeID == "String" {
				g.writeLinef("if !strings.HasPrefix(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if !bytes.HasPrefix(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s prefix rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.Suffix:
			if vc.TypeID == "String" {
				g.writeLinef("if !strings.HasSuffix(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if !bytes.HasSuffix(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s suffix rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.Contains:
			if vc.TypeID == "String" {
				g.writeLinef("if !strings.Contains(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if !bytes.Contains(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s contains rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NotContains:
			if vc.TypeID == "String" {
				g.writeLinef("if strings.Contains(%s, %s) {\n", target, source)
			} else {
				g.writeLinef("if bytes.Contains(%s, %s) {\n", target, source)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s not_contains rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.Pattern:
			if vc.TypeID == "String" {
				g.writeLinef("if ok, _ := regexp.MatchString(%s, %s); !ok {\n", source, target)
			} else {
				g.writeLinef("if ok, _ := regexp.Match(string(%s), %s); !ok {\n", source, target)
			}
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s pattern rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.In:
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
		case parser.NotIn:
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
		case parser.NotNil:
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
		switch rule.Key {
		case parser.MinSize, parser.MaxSize:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.IntValue:
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			case parser.FunctionValue:
				source = vc.GenID("_src")
				if err := g.generateFunction(source, vc, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.Elem:
			// do nothing
		default:
			return errors.New("unknown list annotation")
		}
		switch rule.Key {
		case parser.MinSize:
			g.writeLinef("if len(%s) < int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s MinLen rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.MaxSize:
			g.writeLinef("if len(%s) > int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s MaxLen rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.Elem:
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
		switch rule.Key {
		case parser.MinSize, parser.MaxSize:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.IntValue:
				source = strconv.FormatInt(vt.TypedValue.Int, 10)
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			case parser.FunctionValue:
				source = vc.GenID("_src")
				if err := g.generateFunction(source, vc, vt.TypedValue.Function); err != nil {
					return err
				}
			}
		case parser.NoSparse:
			vt := rule.Specified
			switch vt.ValueType {
			case parser.BoolValue:
				source = strconv.FormatBool(vt.TypedValue.Bool)
			case parser.FieldReferenceValue:
				source = vt.TypedValue.GetFieldReferenceName("p.", vc.StructLike)
			}
		case parser.MapKey, parser.MapValue:
			// do nothing
		default:
			return errors.New("unknown map annotation")
		}
		switch rule.Key {
		case parser.MinSize:
			g.writeLinef("if len(%s) < int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s min_size rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.MaxSize:
			g.writeLinef("if len(%s) > int(%s) {\n", target, source)
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s max_size rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
		case parser.NoSparse:
			g.writeLinef("for _, v := range %s {\n", target)
			g.indent()
			g.writeLinef("if v == nil {\n")
			g.indent()
			g.writeLinef("return fmt.Errorf(\"field %s no_sparse rule failed, current value: %%v\", %s)\n", vc.FieldName, target)
			g.unindent()
			g.writeLine("}")
			g.unindent()
			g.writeLine("}")
		case parser.MapKey:
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
		case parser.MapValue:
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
				source = val.TypedValue.GetFieldReferenceName("p.", st)
			} else {
				source = strconv.FormatInt(val.TypedValue.Int, 10)
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	case "Double":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				source = val.TypedValue.GetFieldReferenceName("p.", st)
			} else {
				source = strconv.FormatFloat(val.TypedValue.Double, 'f', -1, 64)
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	case "String":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				source = val.TypedValue.GetFieldReferenceName("p.", st)
			} else {
				source = "\"" + val.TypedValue.Binary + "\""
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	case "Binary":
		for _, val := range vals {
			var source string
			if val.ValueType == parser.FieldReferenceValue {
				source = val.TypedValue.GetFieldReferenceName("p.", st)
			} else {
				source = "\"" + val.TypedValue.Binary + "\""
			}
			vs = append(vs, typeid2go[typeID]+"("+source+")")
		}
	default:
		return fmt.Errorf("type %s not supported in generate slice", typeID)
	}
	g.writeLinef("%s}\n", strings.Join(vs, ", "))
	return nil
}

func (g *generator) generateEnumSlice(name, enumType string, vals []*parser.ValidationValue, vc *ValidateContext) error {
	if len(vals) == 0 {
		return errors.New("empty validation values")
	}
	g.writeLinef("%s := []", name)
	var vs []string
	g.writeLinef("%s{", enumType)
	for _, val := range vals {
		str, err := g.parseEnumValue(val.TypedValue.Binary, vc)
		if err == nil {
			vs = append(vs, string(str))
		}
	}
	g.writeLinef("%s}\n", strings.Join(vs, ", "))
	return nil
}

func (g *generator) renderValidationValue(vc *ValidateContext, val *parser.ValidationValue) (string, error) {
	switch val.ValueType {
	case parser.DoubleValue:
		return fmt.Sprintf("float64(%f)", val.TypedValue.Double), nil
	case parser.IntValue:
		return fmt.Sprintf("int64(%d)", val.TypedValue.Int), nil
	case parser.FunctionValue:
		source := vc.GenID("_src")
		g.generateFunction(source, vc, val.TypedValue.Function)
		return source, nil
	case parser.FieldReferenceValue:
		return val.TypedValue.GetFieldReferenceName("p.", vc.StructLike), nil
	default:
		return "", fmt.Errorf("value type %s is not supported for equal", val.ValueType)
	}
}

func (g *generator) generateFunction(source string, vc *ValidateContext, f *parser.ToolFunction) error {
	switch f.Name {
	case "len":
		g.writeLinef(source+" := len(%s)\n", f.Arguments[0].TypedValue.GetFieldReferenceName("p.", vc.StructLike))
	case "sprintf":
		g.writeLinef(source + " := fmt.Sprintf(")
		var args []string
		for _, arg := range f.Arguments {
			switch arg.ValueType {
			case parser.BinaryValue:
				args = append(args, "\""+arg.TypedValue.Binary+"\"")
			case parser.FieldReferenceValue:
				args = append(args, arg.TypedValue.GetFieldReferenceName("p.", vc.StructLike))
			}
		}
		g.write(strings.Join(args, ",") + ")\n")
	// binary function
	case "equal", "mod", "add":
		var args []string
		for _, arg := range f.Arguments {
			argName, err := g.renderValidationValue(vc, &arg)
			if err != nil {
				return err
			}
			args = append(args, argName)
		}
		if len(args) < 2 {
			return fmt.Errorf("binary function %s needs at least 2 arguments", f.Name)
		}
		g.write(source + " := " + args[0])
		switch f.Name {
		case "equal":
			g.write(" == ")
		case "mod":
			g.write(" % ")
		case "add":
			g.write(" + ")
		}
		g.write(args[1] + "\n")
	case "now_unix_nano":
		g.write(source + ":= time.Now().UnixNano()\n")
		return nil
	default:
		funcTemplate := g.config.GetFunction(f.Name)
		if funcTemplate == nil {
			return errors.New("unknown function: " + f.Name)
		}
		var buf bytes.Buffer
		err := funcTemplate.Execute(&buf, &struct {
			Source     string
			StructLike *golang.StructLike
			Function   *parser.ToolFunction
		}{
			Source:     source,
			StructLike: vc.StructLike,
			Function:   f,
		})
		if err != nil {
			return fmt.Errorf("execute function %s's template failed: %v", f.Name, err)
		}
		g.write(buf.String())
		g.usedFuncs[funcTemplate] = true
	}
	return nil
}
