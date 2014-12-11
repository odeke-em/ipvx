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
	base               int
	bitCountPerSegment int
	delimiter          string
	fieldCount         int
	maxSegment         int64
	strictFieldCount   bool
}

type IPVX struct {
	Addr           string
	ParsedSegments *[]int64
}

func (ipvx *ipvxBase) create(addr string) (*IPVX, error) {
	split := strings.Split(addr, ipvx.delimiter)
	splitLen := len(split)
	if ipvx.strictFieldCount && splitLen != ipvx.fieldCount {
		return nil, fmt.Errorf("With strictFieldCount, expected exactly %d fields", ipvx.fieldCount)
	}
	// On the other hand if the field count exceeds
	if splitLen > ipvx.fieldCount {
		return nil, fmt.Errorf("Expecting no more than: %d fields", ipvx.fieldCount)
	}

	parsedSegments := make([]int64, splitLen)
	for i, segment := range split {
		trimmed := strings.Trim(segment, " ")
		v, err := strconv.ParseInt(trimmed, ipvx.base, ipvx.bitCountPerSegment)
		if err != nil {
			return nil, err
		}
		if v < 0 {
			return nil, fmt.Errorf("Only expecting values >= 0, got: %v", v)
		}
		if v >= ipvx.maxSegment {
			return nil, fmt.Errorf("Segment overflow: max: %v, got: %v", ipvx.maxSegment, v)
		}
		parsedSegments[i] = v
	}
	ipxObj := &IPVX{
		Addr:           addr,
		ParsedSegments: &parsedSegments,
	}
	return ipxObj, nil
}

func New(addr string, base uint) (*IPVX, error) {
	switch base {
	case IPV4:
		return new4(addr)
		break
	case IPV6:
		return new6(addr)
		break
	}
	return nil, fmt.Errorf("No such base exists!")
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
	osegLen := len(*other.ParsedSegments)

	for i, v = range *self.ParsedSegments {
		if i < osegLen {
			if v != (*other.ParsedSegments)[i] {
				return false
			}
		} else if v != 0x0 {
			return false
		}
	}

	i++
	for i < osegLen {
		v := (*other.ParsedSegments)[i]
		if v != 0x0 {
			return false
		}
		i++
	}
	return true
}

func new4(addr string) (*IPVX, error) {
	ipvb := ipvxBase{
		base:               10,
		bitCountPerSegment: 32,
		delimiter:          ".",
		fieldCount:         4,
		maxSegment:         0xff + 1,
		strictFieldCount:   true,
	}
	return ipvb.create(addr)
}

func new6(addr string) (*IPVX, error) {
	ipvb := ipvxBase{
		base:               16,
		bitCountPerSegment: 32,
		delimiter:          ":",
		fieldCount:         8,
		maxSegment:         0xffff + 1,
	}
	return ipvb.create(addr)
}
