//go:build !integration

package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

func TestString(t *testing.T) {
	t.Parallel()

	envKey := random.String(10)
	envVal := random.String(10)
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKey, envVal))

	tests := []struct {
		inpKey string
		inpDef string
		res    string
	}{
		{envKey, "", envVal},
		{random.String(10), "default", "default"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can parse %+v", test), func(t *testing.T) {
			t.Parallel()

			res := String(test.inpKey, test.inpDef)
			t.Logf("res: %v", res)
			require.Equal(t, test.res, res)
		})
	}
}

func TestStringSlice(t *testing.T) {
	t.Parallel()

	envKey := random.String(10)
	envVal := fmt.Sprintf("%s,%s,%s", random.String(10), random.String(10),
		random.String(10))
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKey, envVal))

	envKeyNoDelim := random.String(10)
	envValNoDelim := random.String(10)
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKeyNoDelim, envValNoDelim))

	tests := []struct {
		inpKey string
		inpDef []string
		res    []string
	}{
		{envKey, []string{}, strings.Split(envVal, ",")},
		{envKeyNoDelim, []string{}, []string{envValNoDelim}},
		{random.String(10), []string{"default"}, []string{"default"}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can parse %+v", test), func(t *testing.T) {
			t.Parallel()

			res := StringSlice(test.inpKey, test.inpDef)
			t.Logf("res: %#v", res)
			require.Equal(t, test.res, res)
		})
	}
}

func TestInt(t *testing.T) {
	t.Parallel()

	envKey := random.String(10)
	envVal := random.Intn(999)
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKey, strconv.Itoa(envVal)))

	tests := []struct {
		inpKey string
		inpDef int
		res    int
	}{
		{envKey, 0, envVal},
		{random.String(10), 99, 99},
		// Do not test conversion failure from env due to use of log.Fatalf().
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can parse %+v", test), func(t *testing.T) {
			t.Parallel()

			res := Int(test.inpKey, test.inpDef)
			t.Logf("res: %v", res)
			require.Equal(t, test.res, res)
		})
	}
}

func TestBool(t *testing.T) {
	t.Parallel()

	envKey := random.String(10)
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKey, "true"))

	tests := []struct {
		inpKey string
		inpDef bool
		res    bool
	}{
		{envKey, false, true},
		{random.String(10), true, true},
		// Do not test conversion failure from env due to use of log.Fatalf().
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can parse %+v", test), func(t *testing.T) {
			t.Parallel()

			res := Bool(test.inpKey, test.inpDef)
			t.Logf("res: %v", res)
			require.Equal(t, test.res, res)
		})
	}
}

func TestDuration(t *testing.T) {
	t.Parallel()

	envKey := random.String(10)
	envVal := random.Intn(999)
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKey, strconv.Itoa(envVal)+"s"))

	tests := []struct {
		inpKey string
		inpDef time.Duration
		res    time.Duration
	}{
		{envKey, 0, time.Duration(envVal) * time.Second},
		{random.String(10), time.Minute, time.Minute},
		// Do not test conversion failure from env due to use of log.Fatalf().
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can parse %+v", test), func(t *testing.T) {
			t.Parallel()

			res := Duration(test.inpKey, test.inpDef)
			t.Logf("res: %#v", res)
			require.Equal(t, test.res, res)
		})
	}
}

func TestByteSlice(t *testing.T) {
	t.Parallel()

	key := make([]byte, 10)
	_, err := rand.Read(key)
	require.NoError(t, err)
	t.Logf("key: %x", key)

	envKey := random.String(10)
	envVal := base64.StdEncoding.EncodeToString(key)
	//nolint:tenv // Require os.Setenv() for t.Parallel(), do not unset.
	require.NoError(t, os.Setenv(envKey, envVal))

	tests := []struct {
		inp string
		res []byte
	}{
		{envKey, key},
		{random.String(10), []byte{}},
		// Do not test conversion failure from env due to use of log.Fatalf().
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can parse %+v", test), func(t *testing.T) {
			t.Parallel()

			res := ByteSlice(test.inp)
			t.Logf("res: %x", res)
			require.Equal(t, test.res, res)
		})
	}
}
