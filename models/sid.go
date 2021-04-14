package models

import (
	"fmt"
	"strings"
)

type SID struct {
	Revision       byte
	NumAuthorities byte
	Authority      []byte
	SubAuthorities []uint32
}

func (s SID) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("S-%v-%v", s.Revision, int(s.Authority[5])))
	for i := 0; i < int(s.NumAuthorities); i++ {
		sb.WriteString(fmt.Sprintf("-%v", s.SubAuthorities[i]))
	}
	return sb.String()
}
