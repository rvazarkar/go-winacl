package models

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
)

type RawSecurityDescriptor []byte
type ParsedSecurityDescriptor struct {
	Buf        *bytes.Buffer
	Descriptor NtSecurityDescriptor
}
type BufferedSecurityDescriptor *bytes.Buffer

type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader
	DACL   ACL
	SACL   ACL
	Owner  windows.SID
	Group  windows.SID
}

type NtSecurityDescriptorHeader struct {
	Revision    byte
	Sbz1        byte
	Control     uint16
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32
	OffsetDacl  uint32
}

func (s NtSecurityDescriptor) String() string {
	return fmt.Sprintf("Parsed Security Descriptor:\n Offsets:\n Owner=%v Group=%v Sacl=%v Dacl=%v\n", s.Header.OffsetOwner, s.Header.OffsetGroup, s.Header.OffsetDacl, s.Header.OffsetSacl)
}
