package logger

import "testing"

func TestRedactQuery(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "only parameter",
			in:   "/login/sso/generate?access_token=SECRET",
			want: "/login/sso/generate?access_token=<redacted>",
		},
		{
			name: "absolute URL",
			in:   "https://account.battle.net/p?access_token=SECRET",
			want: "https://account.battle.net/p?access_token=<redacted>",
		},
		{
			name: "keeps order and repeated parameters",
			in:   "/p?a=1&access_token=SECRET&b=2&b=3",
			want: "/p?a=1&access_token=<redacted>&b=2&b=3",
		},
		{
			name: "case insensitive name",
			in:   "/p?Access_Token=SECRET&Code=SECRET2",
			want: "/p?Access_Token=<redacted>&Code=<redacted>",
		},
		{
			name: "harmless parameters untouched",
			in:   "/p?a=1&b=2",
			want: "/p?a=1&b=2",
		},
		{
			name: "empty value untouched",
			in:   "/p?token=",
			want: "/p?token=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactQuery(tc.in, true); got != tc.want {
				t.Errorf("redactQuery(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got := redactQuery(tc.in, false); got != tc.in {
				t.Errorf("redactQuery(%q, false) = %q, want it unchanged", tc.in, got)
			}
		})
	}
}

func TestRedactHeaderValue(t *testing.T) {
	cases := map[string]string{
		"Bearer abc.def.ghi":   "Bearer <redacted>",
		"Basic dXNlcjpwYXNz":   "Basic <redacted>",
		"opaque-token-without": "<redacted>",
		"":                     "<redacted>",
	}
	for in, want := range cases {
		if got := redactHeaderValue(in); got != want {
			t.Errorf("redactHeaderValue(%q) = %q, want %q", in, got, want)
		}
	}
}
