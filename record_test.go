package main

import "testing"

func TestJoinArgs(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"nmap", "-sV", "10.0.0.1"}, "nmap -sV 10.0.0.1"},
		{[]string{"echo", "hello world"}, `echo 'hello world'`},
		{[]string{"sh", "-c", "printf \"hi\"\n"}, "sh -c 'printf \"hi\"\n'"},
		{[]string{"grep", "it's"}, `grep 'it'\''s'`},
		{[]string{"echo", ""}, `echo ''`},
	}
	for _, c := range cases {
		if got := joinArgs(c.in); got != c.want {
			t.Errorf("joinArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{500, "500B"}, {2048, "2KB"}, {5 * 1024 * 1024, "5MB"}, {3 * 1024 * 1024 * 1024, "3GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsToolName(t *testing.T) {
	for _, ok := range []string{"nmap", "nuclei", "nxc", "ferox-buster", "ffuf2"} {
		if !isToolName(ok) {
			t.Errorf("isToolName(%q) should be true", ok)
		}
	}
	for _, bad := range []string{"", "rm -rf", "a;b", "$(x)", "x y"} {
		if isToolName(bad) {
			t.Errorf("isToolName(%q) should be false", bad)
		}
	}
}
