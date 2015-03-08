// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// IP address parser and comparator for protocols:
// IPv4 and IPv6

package ipvx

import (
	"fmt"
	"testing"
)

func TestInit(t *testing.T) {
	ipv, err := New("", 0)
	if err == nil {
		t.Errorf("Expected an error back!")
	}
	if ipv != nil {
		t.Errorf("Expected a failed init due to an invalid base!")
	}

	ipv, err = New("192.167.23", IPV4)
	fmt.Println()
	if err == nil {
		t.Errorf("Expected an error due to incomplete fields in addr!")
	}
	if ipv != nil {
		t.Errorf("Expected a failed init due to an invalid base!")
	}
}

func TestSegmentLimitsIPV4(t *testing.T) {
	ipv4_invalid := []string{
		"-12.238.23.10",
		"2999.298.29.-10",
		"29.-298.0000029.-10",
	}
	for _, addr := range ipv4_invalid {
		ipv, err := New(addr, IPV4)
		if err == nil {
			t.Errorf("Expected an error on the limits!")
		}
		if ipv != nil {
			t.Errorf("Not expecting ipv object back!")
		}
	}
}

func TestSegmentLimitsIPV6(t *testing.T) {
	ipv4_invalid := []string{
		"fffffce6:-d1ad:ca44:9625:e589:3806:248:8591",
		"0:0:0:0:0:0:0:0:0:ffffffff0",
		"fx0:0:0:0:0:0:0:0:0:f0",
		"99:0:0:f0:0:0:f0:0:f0",
	}
	for _, addr := range ipv4_invalid {
		ipv, err := New(addr, IPV6)
		if err == nil {
			t.Errorf("Expected an error on the limits!")
		}
		if ipv != nil {
			t.Errorf("Not expecting ipv object back!")
		}
	}
}

func TestIPV4(t *testing.T) {
	ipv4, err := New("192.168.1.100", IPV4)
	if err != nil {
		t.Errorf("Expected no error back, instead got %v", err)
	}
	if ipv4 == nil {
		t.Errorf("Was not expecting a nil object back!")
	}
}

func TestIPV6(t *testing.T) {
	ipv6, err := New("192.168.1.100", IPV6)
	if err == nil {
		t.Errorf("Expected an error back!")
	}
	if ipv6 != nil {
		t.Errorf("Was not expecting a nil object back!")
	}

	ipv6A, errA := New("fce6:d1ad:ca44:9625:e589:3806:248:8591", IPV6)
	if errA != nil {
		t.Errorf("Expecting nil error, got: %v", errA)
	}
	if ipv6A == nil {
		t.Errorf("Didn't expect a nil object back!")
	}
	ipv6B, errB := New("fce6:d1ad:ca44:9625:e589:3806:0248:8591", IPV6)
	if errB != nil {
		t.Errorf("No err expected got: %v", errB)
	}

	if !ipv6A.Equal(ipv6B) {
		t.Errorf("Despite padding, should be similar!")
	}
}

func TestPaddingIPV4(t *testing.T) {
	pairs := []struct {
		first string
		last  string
	}{
		{
			first: "10.0.0.0", last: "0000010.0.00000.0",
		},
		{
			first: "192.168.0.10", last: "0192.0168.0.00010",
		},
		{
			first: "8.8.8.8", last: "0008.0008.08.8",
		},
		{
			first: "8.8.4.4", last: "000008.000008.000004.000004",
		},
	}

	for _, pair := range pairs {
		ipv4A, errA := New(pair.first, IPV4)
		if errA != nil {
			t.Errorf("Didn't expect any error, got: %v", errA)
		}
		if ipv4A == nil {
			t.Errorf("Non nil expected!")
		}

		ipv4B, errB := New(pair.last, IPV4)
		if errB != nil {
			t.Errorf("Didn't expect any error, got: %v", errB)
		}
		if ipv4B == nil {
			t.Errorf("Non nil expected!")
		}
		if !ipv4A.Equal(ipv4B) {
			t.Errorf("Expecting A and B to equal!")
		}
	}
}

func TestPaddingIPV4StrictFieldCountNotMatching(t *testing.T) {
	pairs := []struct {
		first string
		last  string
	}{
		{
			first: "192.168.127.83", last: "129.168.127.83",
		},
		{
			first: "8.8.8.8", last: "0080.0008.08.80",
		},
		{
			first: "8.08.04.004", last: "08.08.04.040",
		},
	}

	for _, pair := range pairs {
		ipv4A, errA := New(pair.first, IPV4)
		if errA != nil {
			t.Errorf("Didn't expect any error, got: %v", errA)
		}
		if ipv4A == nil {
			t.Errorf("Non nil expected!")
		}

		ipv4B, errB := New(pair.last, IPV4)
		if errB != nil {
			t.Errorf("Didn't expect any error, got: %v", errB)
		}
		if ipv4B == nil {
			t.Errorf("Non nil expected!")
		}
		if ipv4A.Equal(ipv4B) {
			t.Errorf("Not Expecting A and B to equal!")
		}
	}
}

func TestPaddingIPV6NonStrictFieldCount(t *testing.T) {
	pairs := []struct {
		first string
		last  string
	}{
		{
			first: "fce6:d1ad:ca44:9625:e589:3806:248:8591", last: "fce6:d1ad:ca44:9625:e589:3806:0248:8591",
		},
		{
			first: "2001:0DBB:AC10:FE01:0000:0000:0000:0000", last: "002001:0DBB:AC10:00FE01",
		},
		{
			first: "2001:4860:4860::8888", last: "2001:4860:4860:0000:8888", // Google IPV6 DNS
		},
		{
			first: "2001:4860:4860::8844", last: "2001:4860:4860:0000:8844", // Google IPV6 DNS
		},
	}

	for _, pair := range pairs {
		ipv6A, errA := New(pair.first, IPV6)
		if errA != nil {
			t.Errorf("Didn't expect any error, got: %v", errA)
		}
		if ipv6A == nil {
			t.Errorf("Non nil expected!")
		}

		ipv6B, errB := New(pair.last, IPV6)
		if errB != nil {
			t.Errorf("Didn't expect any error, got: %v", errB)
		}
		if ipv6B == nil {
			t.Errorf("Non nil expected!")
		}
		if !ipv6A.Equal(ipv6B) {
			t.Errorf("Expecting A and B to equal!")
		}
	}
}

func TestPaddingIPV6NonStrictFieldCountNotMatching(t *testing.T) {
	pairs := []struct {
		first string
		last  string
	}{
		{
			first: "fce6:d1ad:ca44:e589:3806:9625:248:8591", last: "fce6:d1ad:ca44:9625:e589:3806:0248:8591",
		},
		{
			first: "2001:0DBB:AC10:FE01:0000:0000:0000", last: "002001:0000:0DBB:AC10:00FE01",
		},
	}
	for _, pair := range pairs {
		ipv6A, errA := New(pair.first, IPV6)
		if errA != nil {
			t.Errorf("Didn't expect any error, got: %v", errA)
		}
		if ipv6A == nil {
			t.Errorf("Non nil expected!")
		}

		ipv6B, errB := New(pair.last, IPV6)
		if errB != nil {
			t.Errorf("Didn't expect any error, got: %v", errB)
		}
		if ipv6B == nil {
			t.Errorf("Non nil expected!")
		}
		if ipv6A.Equal(ipv6B) {
			t.Errorf("Not Expecting A and B to equal!")
		}
	}
}

func TestTrimsIPV4(t *testing.T) {
	ipv4_trimmables := []string{
		"       12.   238.   23.   10   ",
		"        29.    98. 29.  10",
		"192.   168.  0000029  . 10   ",
	}
	for _, addr := range ipv4_trimmables {
		ipv, err := New(addr, IPV4)
		if err != nil {
			t.Errorf("Expecting no errors back!")
		}
		if ipv == nil {
			t.Errorf("Expecting ipv object back!")
		}
	}
}

func TestTrimsIPV6(t *testing.T) {
	ipv6_trimmables := []string{
		"fce6:    d1ad    :ca44    :e589    :3806    :    9625:248:8591",
		"fce6:    d1ad:ca44:9625:e589:3806:0248:    8591",
		"        2001:    0DBB:    AC10:FE01:0000    :0000:0000        ",
		"002001    :0000:    0DBB:AC10:    00FE01",
		"002001    :0000:::AC10:    00FE01", // Optional skip of fields
	}
	for _, addr := range ipv6_trimmables {
		ipv, err := New(addr, IPV6)
		if err != nil {
			t.Errorf("Expecting no errors back, got %v", err)
		}
		if ipv == nil {
			t.Errorf("Expecting ipv object back!")
		}
	}
}

func TestIPV6OptionalityCompletion(t *testing.T) {
	pairs := []struct {
		first string
		last  string
	}{
		{
			first: "dfe::", last: "0dfe:0000:0000:0000:0000:0000:0000:0000",
		},
		{
			first: "fdfe::0ffe", last: "fdfe::0ffe::",
		},
		{
			first: "2001::eef1", last: "2001::eef1::",
		},
	}

	for _, pair := range pairs {
		first, fErr := New(pair.first, IPV6)
		if fErr != nil {
			t.Errorf("expected successful creation of first, instead got: %v", fErr)
		}
		last, sErr := New(pair.last, IPV6)

		if sErr != nil {
			t.Errorf("expected successful creation of last, instead got: %v", sErr)
		}

		if !first.Equal(last) {
			t.Errorf("%v should be equal to %v", first, last)
		}
	}
}
