// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// IP address parser and comparator for protocols:
// IPv4 and IPv6

package ipvx

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	IPV4 = 1 << iota
	IPV6
)

type ipvxBase struct {
	base        int
	segBitCount int
	delimiter   string
	fieldCount  int
	// maxSegment is the final sanity check to catch any sneaky
	// overflow bugs past the alloted bit size of the protocol
	maxSegment       int64
	padSegIfBlank    bool
	strictFieldCount bool
}

type IPVX struct {
	Addr           string
	ParsedSegments []int64
}

func (ipvx *ipvxBase) create(addr string) (*IPVX, error) {
	split := strings.Split(addr, ipvx.delimiter)
	splitLen := len(split)
	if ipvx.strictFieldCount && splitLen != ipvx.fieldCount {
		return nil, fmt.Errorf("with strictFieldCount, expected exactly %d fields", ipvx.fieldCount)
	}
	// On the other hand if the field count exceeds the desired field count always an error
	if splitLen > ipvx.fieldCount {
		return nil, fmt.Errorf("expecting no more than: %d fields", ipvx.fieldCount)
	}

	parsedSegments := make([]int64, splitLen)
	for i, segment := range split {
		trimmed := strings.Trim(segment, " ")
		if trimmed == "" && ipvx.padSegIfBlank {
			trimmed = "0"
		}
		v, err := strconv.ParseInt(trimmed, ipvx.base, ipvx.segBitCount)
		if err != nil {
			return nil, err
		}
		if v < 0 {
			return nil, fmt.Errorf("only expecting values >= 0, got: %v", v)
		}
		// Ideally this condition should never match.
		// This is the last sanity check to catch overflows.
		if v > ipvx.maxSegment {
			return nil, fmt.Errorf("segment overflow: max: %v, got: %v", ipvx.maxSegment, v)
		}
		parsedSegments[i] = v
	}
	ipxObj := &IPVX{
		Addr:           addr,
		ParsedSegments: parsedSegments,
	}
	return ipxObj, nil
}

func New(addr string, base uint) (*IPVX, error) {
	switch base {
	case IPV4:
		return new4(addr)
	case IPV6:
		return new6(addr)
	}
	return nil, fmt.Errorf("unknown protocol with base %d", base)
}

func (self *IPVX) Equal(other *IPVX) bool {
	if other == nil {
		return false
	}
	if self.Addr == other.Addr {
		return true
	}

	i := 0
	v := int64(0)
	otherSegLen := len(other.ParsedSegments)

	for i, v = range self.ParsedSegments {
		if i < otherSegLen {
			if v != other.ParsedSegments[i] {
				return false
			}
		} else if v != 0x0 {
			return false
		}
	}

	i++
	for i < otherSegLen {
		if other.ParsedSegments[i] != 0x0 {
			return false
		}
		i++
	}
	return true
}

func new4(addr string) (*IPVX, error) {
	ipvb := ipvxBase{
		base:             10,
		delimiter:        ".",
		fieldCount:       4,
		maxSegment:       0xff,
		segBitCount:      8 + 1, // One extra for the sign bit.
		strictFieldCount: true,
	}
	return ipvb.create(addr)
}

func new6(addr string) (*IPVX, error) {
	ipvb := ipvxBase{
		base:          16,
		delimiter:     ":",
		fieldCount:    8,
		maxSegment:    0xffff,
		padSegIfBlank: true,
		segBitCount:   16 + 1, // One extra for the sign bit.
	}
	return ipvb.create(addr)
}
