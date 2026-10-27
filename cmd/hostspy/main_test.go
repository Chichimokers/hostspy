package main

import (
	"testing"
	"time"
)

func TestInterceptPortsValidation(t *testing.T) {
	base := Config{ListenHTTPS: ":443", ListenHTTP: ":80"}

	cfg := base
	cfg.InterceptPorts = []int{1119, 1119, 7019}
	ports, err := interceptPorts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 2 || ports[0] != 1119 || ports[1] != 7019 {
		t.Fatalf("ports = %v, want [1119 7019]", ports)
	}

	cfg.InterceptPorts = []int{443}
	if _, err := interceptPorts(cfg); err == nil {
		t.Error("expected a conflict with listenHTTPS")
	}

	cfg.InterceptPorts = []int{80}
	if _, err := interceptPorts(cfg); err == nil {
		t.Error("expected a conflict with listenHTTP")
	}

	cfg.ListenHTTP = ""
	cfg.InterceptPorts = []int{0}
	if _, err := interceptPorts(cfg); err == nil {
		t.Error("expected an invalid port error")
	}
	cfg.InterceptPorts = []int{65536}
	if _, err := interceptPorts(cfg); err == nil {
		t.Error("expected an out-of-range port error")
	}

	cfg.InterceptPorts = nil
	ports, err = interceptPorts(cfg)
	if err != nil || ports != nil {
		t.Fatalf("empty interceptPorts = %v, %v; want nil, nil", ports, err)
	}
}

func TestMilliseconds(t *testing.T) {
	if got := milliseconds(0, 10*time.Second); got != 10*time.Second {
		t.Errorf("zero = %v, want fallback", got)
	}
	if got := milliseconds(-5, time.Second); got != time.Second {
		t.Errorf("negative = %v, want fallback", got)
	}
	if got := milliseconds(2500, time.Second); got != 2500*time.Millisecond {
		t.Errorf("2500 = %v, want 2.5s", got)
	}
}
