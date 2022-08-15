# thrift-gen-validator

thrift-gen-validator is a thriftgo plugin to generate struct validators.
Users can define validation rule for struct-like(struct/union/exception) in Thrift file, then the generator will generate `IsValid() error` method for those structs.

for example:

```Thrift
enum MapKey {
    A, B, C, D, E, F
}

struct Example {
    1: string Message (vt.min_size = "30") // length of Message should be greater than or equal to 30
    2: i32 ID (vt.ge = "10000") // ID must be greater than or euqal to 10000
    3: list<double> Values (vt.elem.gt = "0.25") // element of Values must be greater than 0.25
    4: map<MapKey, string> KeyValues (vt.key.defined_only = "true") // value of KeyValues'key must be defined in MapKey
}
```

generated method:

```go
func (p *Example) IsValid() error {
	if len(p.Message) < int(30) {
		return fmt.Errorf("field Message min_len rule failed, current value: %d", len(p.Message))
	}
	if p.ID < int32(10000) {
		return fmt.Errorf("field ID ge rule failed, current value: %v", p.ID)
	}
	for i := 0; i < len(p.Values); i++ {
		_elem := p.Values[i]
		if _elem <= float64(0.25) {
			return fmt.Errorf("field _elem gt rule failed, current value: %v", _elem)
		}
	}
	for k := range p.KeyValues {
		if k.String() == "<UNSET>" {
			return fmt.Errorf("field k defined_only rule failed")
		}
	}
	return nil
}
```

## Install

`go install github.com/cloudwego/thrift-gen-validator`

## Usage

### Thriftgo

`thriftgo -g go -p validator my.thrift`

### Kitex

`kitex --thrift-plugin validator -service a.b.c my.thrift`

## Feature Matrix

prefix `vt`, short for "validation"

### Numeric(i8/i16/i32/i64/double)

| Rule      |                                          |
| --------- | ---------------------------------------- |
| vt.const  | must be specified value                  |
| vt.lt     | less than the specified value            |
| vt.le     | less than or equal to specified value    |
| vt.gt     | greater than the specified value         |
| vt.ge     | greater than or equal to specified value |
| vt.in     | must be in specified values              |
| vt.not_in | must not be in specified values          |

### Bool

| Rule     |                         |
| -------- | ----------------------- |
| vt.const | must be specified value |

### String/Binary

| Rule            |                                  |
| --------------- | -------------------------------- |
| vt.const        | must be specified value          |
| vt.pattern      | regexp pattern                   |
| vt.prefix       | prefix must be specified value   |
| vt.suffix       | suffix must be specified value   |
| vt.contains     | must contain specified value     |
| vt.not_contains | must not contain specified value |
| vt.min_size     | min size                         |
| vt.max_size     | max size                         |

### Enum

| Rule            |                         |
| --------------- | ----------------------- |
| vt.const        | must be specified value |
| vt.defined_only | must be defined value   |

### Set/List

| Rule        |                       |
| ----------- | --------------------- |
| vt.min_size | min size              |
| vt.max_size | max size              |
| vt.elem     | rule for list element |

### Map

| Rule         |                                   |
| ------------ | --------------------------------- |
| vt.min_size  | min size                          |
| vt.max_size  | max size                          |
| vt.key       | rule for map key                  |
| vt.value     | rule for map value                |
| vt.no_sparse | map value must be non-nil pointer |

### Struct Field

| Rule    |                                  |
| ------- | -------------------------------- |
| vt.skip | skip struct recursive validation |

### Struct

| Rule      |                           |
| --------- | ------------------------- |
| vt.assert | expression should be true |

### Special Value

1. Field Reference. We can use another field as a validation value.
2. Validation Function. We can use those functions to provide extensive validation ability.

#### Field Reference Example

```Thrift
struct Example {
    1: string StringFoo (vt.max_size = "$MaxStringSize")
    2: i32 MaxStringSize
}
```

#### Validation Function

```Thrift
struct Example {
    1: string MaxString
    2: list<string> StringList (vt.elem.max_size = "@len($MaxString)")
}
```

| function name | arguments                                             | results                                                | remarks                                 |
| ------------- | ----------------------------------------------------- | ------------------------------------------------------ | --------------------------------------- |
| len           | 1: container filed                                    | 1: length of container (integer)                       | just like `len` of go                   |
| sprintf       | 1: format string <br /> 2+: arguments matching format | 1: formatted string (string)                           | just like `fmt.Sprintf` of go           |
| now_unix_nano | none                                                  | 1: nano seconds (int64)                                | just like `time.Now().UnixNano()` of go |
| equal         | 1, 2: comparable values                               | 1: whether two arguments is equal (bool)               | just like `==` of go                    |
| mod           | 1, 2: integer                                         | 1: remainder of $1 / $2 (integer)                      | just like `%` of go                     |
| add           | 1, 2: both are numeric or string                      | 1: sum of two arguments (integer or float64 or string) | just like `+` of go                     |

#### Customized Validation Function

Now you can use parameter `func` to customize your validation function. Like below:  
`thriftgo -g go -p validator:func=my_func=path_to_template.txt my.thrift`  
`my_func` is the function name, `path_to_template.txt` is the path to template file which should be a go template.
Available template variables:
| variable name | meaning                               | type                                                             |
| ------------- | ------------------------------------- | ---------------------------------------------------------------- |
| Source        | variable name that rule will refer to | string                                                           |
| StructLike    | ast of current struct/union/exception | *"github.com/cloudwego/thriftgo/generator/golang".StructLike     |
| Function      | data of current function              | *"github.com/cloudwego/thrift-gen-validator/parser".ToolFunction |

## Example

### Kitex Middleware Example

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cloudwego/kitex-examples/kitex_gen/api"
	"github.com/cloudwego/kitex-examples/kitex_gen/api/echo"
	"github.com/cloudwego/kitex/client"
	"github.com/cloudwego/kitex/pkg/endpoint"
	"github.com/cloudwego/kitex/server"
)

func ValidatorMW(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, args, result interface{}) (err error) {
		if gfa, ok := args.(interface{ GetFirstArgument() interface{} }); ok {
			req := gfa.GetFirstArgument()
			if rv, ok := req.(interface{ IsValid() error }); ok {
				if err := rv.IsValid(); err != nil {
					return fmt.Errorf("request data is not valid:%w", err)
				}
			}
		}
		err = next(ctx, args, result)
		if err != nil {
			return err
		}
		if gr, ok := result.(interface{ GetResult() interface{} }); ok {
			resp := gr.GetResult()
			if rv, ok := resp.(interface{ IsValid() error }); ok {
				if err := rv.IsValid(); err != nil {
					return fmt.Errorf("response data is not valid:%w", err)
				}
			}
		}
		return nil
	}
}

// for client
func main() {
	cli := echo.MustNewClient("service_name", client.WithMiddleware(ValidatorMW))
	resp, err := client.Echo(context.Background(), &api.Request{Message: "my request"})
	if err != nil {
		log.Println(err.Error())
	} else {
		log.Println(resp)
	}
}

// for server
func main() {
	svr := echo.NewServer(new(EchoImpl), server.WithMiddleware(ValidatorMW))
	err := svr.Run()
	if err != nil {
		log.Println(err.Error())
	}
}
```

### Customize Validation Function Example
If we have a `my.thrift` like below:

```Thrift
struct Example {
    1: string Message (vt.max_size = "@my_length()")
}
```

And assumes that we want to the max length of Message is 10, we can write a template file `my_length.txt` like below:

```template
{{- .Source}} := 10 /*my length*/
```

Then we can use command below to generate a validator file:  
`thriftgo -g go -p validator:func=my_length=my_length.txt my.thrift`

We will get a `IsValid() error` like below:

```go
func (p *ValidatorExample) IsValid() error {
	_src := 10 /*my length*/
	if len(p.Message) > int(_src) {
		return fmt.Errorf("field Message max_len rule failed, current value: %d", len(p.Message))
	}
	return nil
}
```

`{{.Source}}` indicates `_src` which will be used in `if len(p.Message) > int(_src) {`, so all the thing the function template need to do is assign a value to `_src` aka `{{.Source}}`. In the above example, `{{- .Source}} := + 10 /*my length*/` will do.

Now let's see a more complex example. Assumes that we have a `my.thrift` like below:

```Thrift
struct Example {
    1: string Message (vt.max_size = "@fix_length($MaxLength)")
    2: i64 MaxLength
}
```

And assumes that we want to the max length of Message is the sum of MaxLength and 10, we can write a template file `fix_length.txt` like below:

```template
{{- $arg0 := index .Function.Arguments 0}}
{{- $reference := $arg0.TypedValue.GetFieldReferenceName "p." .StructLike}}
{{- .Source}} := {{$reference}} + 10 /*length fix*/
```

Then we can use command below to generate a validator file:  
`thriftgo -g go -p validator:func=fix_length=fix_length.txt my.thrift`

We will get a `IsValid() error` like below:

```go
func (p *ValidatorExample) IsValid() error {
	_src := p.MaxLength + 10 /*length fix*/
	if len(p.Message) > int(_src) {
		return fmt.Errorf("field Message max_len rule failed, current value: %d", len(p.Message))
	}
	return nil
}
```

`{{$arg0 := index .Function.Arguments 0}}` is used to get the first argument of the function. `{{$reference := $arg0.TypedValue.GetFieldReferenceName "p." .StructLike}}` is used to get the reference name of the first argument, for there `p.MaxLength`.

In some scenarios, we might want to import some extra packages, for example, if we want to get some enviroment variables, we need to import `os` package which is not in the default import list. In this case, we can add following statement to function template file:

```template
{{define "Import"}}
"os"
{{end}}
{{define "ImportGuard"}}
_ = os.Exit
{{end}}
```

Then we can get a validator go file header like below:

```go
import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// unused protection
var (
	_ = fmt.Formatter(nil)
	_ = (*bytes.Buffer)(nil)
	_ = (*strings.Builder)(nil)
	_ = reflect.Type(nil)
	_ = (*regexp.Regexp)(nil)
	_ = time.Nanosecond
	_ = os.Exit
)
```

You can go to [examples/custom-function](/examples/custom-function/) to see the complete example. And you can view the generated code in [examples/custom-function/gen-go/my](/examples/custom-function/gen-go/my/).
