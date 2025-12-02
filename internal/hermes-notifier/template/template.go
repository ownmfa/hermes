// Package template provides functions to generate HTML-safe output from
// templates.
package template

import (
	"html/template"
	"strings"
)

// Generate generates HTML-safe output from templates using the Go template
// engine: https://golang.org/pkg/html/template/
func Generate(displayName, passcode, templ string) (string, error) {
	env := map[string]any{
		"displayName": displayName,
		"passcode":    passcode,
	}

	t, err := template.New("template").Parse(templ)
	if err != nil {
		return "", err
	}

	res := &strings.Builder{}
	err = t.Execute(res, env)
	if err != nil {
		return "", err
	}

	return res.String(), nil
}
