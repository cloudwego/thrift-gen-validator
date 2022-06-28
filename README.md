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
Numeric(i8/i16/i32/i64/double):

| Rule      |                                          |
| --------- | ---------------------------------------- |
| vt.const  | must be specified value                  |
| vt.lt     | less than the specified value            |
| vt.le     | less than or equal to specified value    |
| vt.gt     | greater than the specified value         |
| vt.ge     | greater than or equal to specified value |
| vt.in     | must be in specified values              |
| vt.not_in | must not be in specified values          |

Bool:

| Rule     |                         |
| -------- | ----------------------- |
| vt.const | must be specified value |

String/Binary:

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

Bool:

| Rule     |                         |
| -------- | ----------------------- |
| vt.const | must be specified value |

Enum:

| Rule            |                         |
| --------------- | ----------------------- |
| vt.const        | must be specified value |
| vt.defined_only | must be defined value   |

Set/List:

| Rule        |                       |
| ----------- | --------------------- |
| vt.min_size | min size              |
| vt.max_size | max size              |
| vt.elem     | rule for list element |

Map:

| Rule         |                                   |
| ------------ | --------------------------------- |
| vt.min_size  | min size                          |
| vt.max_size  | max size                          |
| vt.key       | rule for map key                  |
| vt.value     | rule for map value                |
| vt.no_sparse | map value must be non-nil pointer |

Struct Field:

| Rule    |                                  |
| ------- | -------------------------------- |
| vt.skip | skip struct recursive validation |

Struct
| Rule      |                           |
| --------- | ------------------------- |
| vt.assert | expression should be true |

Special Value:

1. Field Reference. We can use another field as a validation value.
2. Validation Function. We can use those functions to provide extensive validation ability.

Field Reference Example:

```Thrift
struct Example {
    1: string StringFoo (vt.max_size = "$MaxStringSize")
    2: i32 MaxStringSize
}
```

Validation Function:

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

## Example

### Kitex Middleware Example

```go
package main

import (
 "context"
 "fmt"
 "log"

 "github.com/cloudwego/kitex/client"
 "github.com/cloudwego/kitex/pkg/endpoint"
 "github.com/cloudwego/kitex/server"
 "github.com/cloudwego/kitex-examples/kitex_gen/api/echo"
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
