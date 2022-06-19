package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testData struct {
	input    string
	expected string
}

func TestUnescape(t *testing.T) {
	tests := []testData{
		{
			input:    "This is a test",
			expected: "This is a test",
		},
		{
			input:    "",
			expected: "",
		},
		{
			input:    "This is \"a\" test",
			expected: "This is a test",
		},
		{
			input:    "This \\is a test",
			expected: "This is a test",
		},
		{
			input:    "This is \\\"a\"\\ test",
			expected: "This is a test",
		},
	}

	for _, v := range tests {
		t.Run("", func(t *testing.T) {
			out := Unescape(v.input)
			assert.Equal(t, v.expected, out)
		})
	}
}
