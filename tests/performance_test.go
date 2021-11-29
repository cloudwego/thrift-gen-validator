package tests

import (
	"fmt"
	"strings"
	"testing"

	gpv "github.com/go-playground/validator/v10"
)

type Simple struct {
	Integer int    `validate:"gte=0,lte=130"`
	String  string `validate:"startswith=my"`
}

var TestSimple = &Simple{
	Integer: 100,
	String:  "mymymy",
}

func (p *Simple) IsValid() error {
	if p.Integer < 0 {
		return fmt.Errorf("field %v rule gte failed", 0)
	}
	if p.Integer > 130 {
		return fmt.Errorf("field %v rule lte failed", 0)
	}
	if !strings.HasPrefix(p.String, "my") {
		return fmt.Errorf("field %v rule prefix failed", 1)
	}
	return nil
}

func BenchmarkValidatorSimple(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		TestSimple.IsValid()
	}
}

func BenchmarkGoPlaygroundValidatorSimple(b *testing.B) {
	validate := gpv.New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validate.Struct(TestSimple)
	}
}
