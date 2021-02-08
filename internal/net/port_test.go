package net

import "testing"

func TestValidPort(t *testing.T) {
	type args struct {
		port uint
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "too low",
			args: args{
				port: 0,
			},
			want: false,
		},
		{
			name: "too high",
			args: args{
				port: 70000,
			},
			want: false,
		},
		{
			name: "just right",
			args: args{
				port: 8080,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidPort(tt.args.port); got != tt.want {
				t.Errorf("ValidPort() = %v, want %v", got, tt.want)
			}
		})
	}
}
