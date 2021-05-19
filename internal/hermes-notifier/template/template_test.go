// +build !integration

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
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			res, err := Generate(lTest.inpDisplayName, lTest.inpPasscode,
				lTest.inpTempl)
			t.Logf("res, err: %v, %#v", res, err)
			require.Equal(t, lTest.res, res)
			if lTest.err == "" {
				require.NoError(t, err)
			} else {
				require.Contains(t, err.Error(), lTest.err)
			}
		})
	}
}
