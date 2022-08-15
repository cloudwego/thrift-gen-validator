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

package config

import (
	"fmt"
	"io/ioutil"
	"strings"
	"text/template"
)

// Config .
type Config struct {
	funcs map[string]*template.Template
}

// Unpack restores the Config from a slice of "key=val" strings.
func (c *Config) Unpack(args []string) error {
	c.funcs = make(map[string]*template.Template)
	for _, a := range args {
		parts := strings.SplitN(a, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid argument: '%s'", a)
		}
		name, value := parts[0], parts[1]
		switch name {
		case "func":
			parts := strings.SplitN(value, "=", 2)
			funcName := parts[0]
			funcPath := parts[1]
			if _, ok := c.funcs[funcName]; ok {
				return fmt.Errorf("duplicate customized tool function: '%s'", funcName)
			}
			funcTemplate, err := ioutil.ReadFile(funcPath)
			if err != nil {
				return fmt.Errorf("read function template failed: %v", err)
			}
			t := template.New("function:" + funcName)
			t, err = t.Parse(string(funcTemplate))
			if err != nil {
				return fmt.Errorf("parse customized function %s's template failed: %v", funcName, err)
			}
			c.funcs[funcName] = t
		}
	}
	return nil
}

func (c *Config) GetFunction(name string) *template.Template {
	return c.funcs[name]
}
