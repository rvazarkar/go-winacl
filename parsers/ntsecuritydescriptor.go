package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/rvazarkar/go-winacl/models"
)

func ParseNtSecurityDescriptor(ntSecurityDescriptorBytes []byte) (models.NtSecurityDescriptor, error) {
	var buf = bytes.NewBuffer(ntSecurityDescriptorBytes)
	ntsd := models.NtSecurityDescriptor{}
	ntsd.Header = ReadNTSDHeader(buf)
	ntsd.DACL = ReadACL(buf)

	return ntsd, nil
}

func ReadNTSDHeader(buf *bytes.Buffer) models.NtSecurityDescriptorHeader {
	var descriptor = models.NtSecurityDescriptorHeader{}

	binary.Read(buf, binary.LittleEndian, &descriptor.Revision)
	binary.Read(buf, binary.LittleEndian, &descriptor.Sbz1)
	binary.Read(buf, binary.LittleEndian, &descriptor.Control)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetOwner)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetGroup)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetSacl)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetDacl)

	return descriptor
}

func ReadACLHeader(buf *bytes.Buffer) models.ACLHeader {
	var header = models.ACLHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Revision)
	binary.Read(buf, binary.LittleEndian, &header.Sbz1)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	binary.Read(buf, binary.LittleEndian, &header.AceCount)
	binary.Read(buf, binary.LittleEndian, &header.Sbz2)

	return header
}

func ReadACL(buf *bytes.Buffer) models.ACL {
	acl := models.ACL{}
	acl.Header = ReadACLHeader(buf)
	for i := 0; i < int(acl.Header.AceCount); i++ {
		fmt.Printf("Ace Index %v\n", i)
		ace := ParseAce(buf)
		fmt.Println(ace)
	}

	return acl
}
