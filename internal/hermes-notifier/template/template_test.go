//go:build !integration

package template

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inpDisplayName string
		inpPasscode    string
		inpTempl       string
		res            string
		err            string
	}{
		{
			"", "", `test`, "test", "",
		},
		{
			"app name", "1234567",
			`Your {{.displayName}} verification code is: {{.passcode}}.`,
			"Your app name verification code is: 1234567.", "",
		},
		{
			"", "", `{{if`, "", "unclosed action",
		},
		{
			"", "", `{{template "aaa"}}`, "", "no such template",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can generate %+v", test), func(t *testing.T) {
			t.Parallel()

			res, err := Generate(test.inpDisplayName, test.inpPasscode,
				test.inpTempl)
			t.Logf("res, err: %v, %#v", res, err)
			require.Equal(t, test.res, res)
			if test.err == "" {
				require.NoError(t, err)
			} else {
				require.Contains(t, err.Error(), test.err)
			}
		})
	}
}
