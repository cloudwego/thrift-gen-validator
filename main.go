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

package main

import (
	"flag"
	"os"

	"github.com/cloudwego/thrift-gen-validator/validator"
)

func main() {
	var queryVersion bool
	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	f.BoolVar(&queryVersion, "version", false, "Show the version of thrift-gen-validator")
	err := f.Parse(os.Args[1:])
	if err != nil {
		println(err)
		os.Exit(2)
	}

	if queryVersion {
		println(validator.Version)
		os.Exit(0)
	}

	os.Exit(validator.Run())
}
