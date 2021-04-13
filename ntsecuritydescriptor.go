package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
)

type RawSecurityDescriptor []byte

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

type ACL struct {
	Header ACLHeader
}

type ACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}

func ParseNtSecurityDescriptor(ntSecurityDescriptorBytes RawSecurityDescriptor) (NtSecurityDescriptor, error) {
	buf := bytes.NewBuffer(ntSecurityDescriptorBytes)
	ntsd := NtSecurityDescriptor{}
	ntsd.Header = ReadNTSDHeader(buf)
	ntsd.DACL = ReadACL(buf)

	return ntsd, nil
}

func ReadNTSDHeader(buf *bytes.Buffer) NtSecurityDescriptorHeader {
	var descriptor = NtSecurityDescriptorHeader{}

	binary.Read(buf, binary.LittleEndian, &descriptor.Revision)
	binary.Read(buf, binary.LittleEndian, &descriptor.Sbz1)
	binary.Read(buf, binary.LittleEndian, &descriptor.Control)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetOwner)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetGroup)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetSacl)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetDacl)

	return descriptor
}

func ReadACLHeader(buf *bytes.Buffer) ACLHeader {
	var header = ACLHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Revision)
	binary.Read(buf, binary.LittleEndian, &header.Sbz1)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	binary.Read(buf, binary.LittleEndian, &header.AceCount)
	binary.Read(buf, binary.LittleEndian, &header.Sbz2)

	return header
}

func ReadACL(buf *bytes.Buffer) ACL {
	acl := ACL{}
	acl.Header = ReadACLHeader(buf)

	return acl
}
