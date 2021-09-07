all: function.peg.go

function.peg.go: function.peg
	which peg >/dev/null || go install github.com/pointlander/peg@latest
	peg ./function.peg

