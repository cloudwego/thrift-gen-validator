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

Struct

| Rule    |                                  |
| ------- | -------------------------------- |
| vt.skip | skip struct recursive validation |

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
for now, only `len` function is available.