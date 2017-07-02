package kubetoken

import "testing"

func TestEscapeDN(t *testing.T) {
	tests := []struct {
		unsafe string
		want   string
	}{
		{"example", "example"},
		{"exam-pl-e", "exam-pl-e"},
		{"Last, First", `Last\, First`},
		{"Windows 2000/XP", `Windows 2000\/XP`},
		{`Sales\Engr`, `Sales\\Engr`},
		{`E#Test`, `E\#Test`},
		{`firstname;lastname`, `firstname\;lastname`},
		{`</head>`, `\<\/head\>`},
		{`admin,OU=admins`, `admin\,OU\=admins`},
		{`princess+toadstool`, `princess\+toadstool`},
	}
	for _, tt := range tests {
		got := escapeDN(tt.unsafe)
		if got != tt.want {
			t.Errorf("escapeDN(%q): got %q, want %q", tt.unsafe, got, tt.want)
		}
	}
}
