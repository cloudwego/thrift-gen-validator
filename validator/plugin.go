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
	"os"

	"github.com/cloudwego/thriftgo/plugin"
)

// PluginName is the link name when the kitex binary is used as a plugin for thriftgo.
const PluginName = "thrift-gen-kitex"

// TheUseOptionMessage indicates that the generating of kitex_gen is aborted due to the -use option.
const TheUseOptionMessage = "kitex_gen is not generated due to the -use option"

// Run is an entry of the plugin mode of kitex for thriftgo.
// It reads a plugin request from the standard input and writes out a response.
func Run(req *plugin.Request) int {
	var warnings []string

	g, err := newGenerator(req)
	if err != nil {
		return exit(&plugin.Response{Warnings: []string{err.Error()}})
	}
	contents, err := g.generate()
	if err != nil {
		return exit(&plugin.Response{Warnings: []string{err.Error()}})
	}

	warnings = append(warnings, g.warnings...)
	for i := range warnings {
		warnings[i] = "[thrift-gen-validator] " + warnings[i]
	}
	res := &plugin.Response{
		Warnings: warnings,
		Contents: contents,
	}

	return exit(res)
}

func exit(res *plugin.Response) int {
	data, err := plugin.MarshalResponse(res)
	if err != nil {
		println("Failed to marshal response:", err.Error())
		return 1
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		println("Error at writing response out:", err.Error())
		return 1
	}
	return 0
}
