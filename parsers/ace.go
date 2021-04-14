package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/rvazarkar/go-winacl/models"
)

func ParseAce(buf *bytes.Buffer) models.ACE {
	ace := models.ACE{}

	ace.Header = ReadACEHeader(buf)
	binary.Read(buf, binary.LittleEndian, &ace.AccessMask)
	switch ace.Header.Type {
	case models.AceTypeAccessAllowed, models.AceTypeAccessDenied, models.AceTypeSystemAudit, models.AceTypeSystemAlarm, models.AceTypeAccessAllowedCallback, models.AceTypeAccessDeniedCallback, models.AceTypeSystemAuditCallback, models.AceTypeSystemAlarmCallback:
		ace.ObjectAce = ReadBasicAce(buf, ace.Header.Size)
	case models.AceTypeAccessAllowedObject, models.AceTypeAccessDeniedObject, models.AceTypeSystemAuditObject, models.AceTypeSystemAlarmObject, models.AceTypeAccessAllowedCallbackObject, models.AceTypeAccessDeniedCallbackObject, models.AceTypeSystemAuditCallbackObject, models.AceTypeSystemAlarmCallbackObject:
		ace.ObjectAce = ReadAdvancedAce(buf, ace.Header.Size)
	}

	return ace
}

func ReadACEHeader(buf *bytes.Buffer) models.ACEHeader {
	header := models.ACEHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Type)
	binary.Read(buf, binary.LittleEndian, &header.Flags)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	return header
}

func ReadBasicAce(buf *bytes.Buffer, totalSize uint16) models.BasicAce {
	oa := models.BasicAce{}

	if sid, err := ReadSID(buf, int(totalSize-8)); err != nil {
		fmt.Printf("Error reading sid: %v\n", err)
	} else {
		oa.SecurityIdentifier = sid
	}
	return oa
}

func ReadAdvancedAce(buf *bytes.Buffer, totalSize uint16) models.AdvancedAce {
	oa := models.AdvancedAce{}
	binary.Read(buf, binary.LittleEndian, &oa.Flags)
	offset := 12
	if (oa.Flags & uint32(models.ACEInheritanceFlagsObjectTypePresent)) != 0 {
		oa.ObjectType = ReadGUID(buf)
		offset += 16
	}

	if (oa.Flags & uint32(models.ACEInheritanceFlagsInheritedObjectTypePresent)) != 0 {
		oa.InheritedObjectType = ReadGUID(buf)
		offset += 16
	}

	// Header+AccessMask is 16 bytes, other members are 36 bytes.
	if sid, err := ReadSID(buf, int(totalSize)-offset); err != nil {
		fmt.Printf("Error reading sid: %v\n", err)
	} else {
		oa.SecurityIdentifier = sid
	}
	return oa
}
