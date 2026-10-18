package main

import (
	"reflect"
	"testing"
)

func TestArguments(t *testing.T) {
	good := map[string]struct {
		args []string
		want options
	}{
		"meters as the server runs it": {[]string{"meters", "--parent", "4321"}, options{mode: "meters", parent: 4321}},
		"outside as the server runs it": {
			[]string{"outside", "--parent", "4321", "--engine", `C:\Program Files\Net Switch\engine\sing-box.exe`},
			options{mode: "outside", parent: 4321, engine: `C:\Program Files\Net Switch\engine\sing-box.exe`},
		},
		"once, for tests":    {[]string{"outside", "--once"}, options{mode: "outside", once: true}},
		"single-dash flags":  {[]string{"meters", "-once", "-parent=7"}, options{mode: "meters", parent: 7, once: true}},
		"an empty engine":    {[]string{"outside", "--engine", ""}, options{mode: "outside"}},
		"no parent to watch": {[]string{"meters"}, options{mode: "meters"}},
		// What the startup task runs: everything after the program is its own,
		// even arguments that look like the helper's flags.
		"run the server hidden": {
			[]string{"run", `C:\Program Files\Net Switch\runtime\node.exe`, `C:\Program Files\Net Switch\server.mjs`, "--user-data", `C:\Users\A B\AppData\Local\Net Switch`, "--once"},
			options{
				mode:        "run",
				program:     `C:\Program Files\Net Switch\runtime\node.exe`,
				programArgs: []string{`C:\Program Files\Net Switch\server.mjs`, "--user-data", `C:\Users\A B\AppData\Local\Net Switch`, "--once"},
			},
		},
		"run with no arguments": {[]string{"run", `C:\x.exe`}, options{mode: "run", program: `C:\x.exe`, programArgs: []string{}}},
	}
	for name, c := range good {
		got, err := parseArgs(c.args)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, %v; want %+v", name, got, err, c.want)
		}
	}

	bad := map[string][]string{
		"no mode":                       {},
		"unknown mode":                  {"speeds"},
		"engine for the meters":         {"meters", "--engine", "x"},
		"a stray argument":              {"meters", "extra"},
		"a parent that is not a number": {"meters", "--parent", "server"},
		"a parent out of range":         {"meters", "--parent", "4294967296"},
		"run without a program":         {"run"},
		"run with an empty program":     {"run", ""},
	}
	for name, args := range bad {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("%s: %v was accepted", name, args)
		}
	}
}
