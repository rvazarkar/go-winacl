package go_winacl

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"unsafe"
)

type AceType byte

const (
	AccessAllowed AceType = iota
	AccessDenied
	SystemAudit
	SystemAlarm
	AccessAllowedCompound
	AccessAllowedObject
	AccessDeniedObject
	SystemAuditObject
	SystemAlarmObject
	AccessAllowedCallback
	AccessDeniedCallback
	AccessAllowedCallbackObject
	AccessDeniedCallbackObject
	SystemAuditCallback
	SystemAlarmCallback
	SystemAuditCallbackObject
	SystemAlarmCallbackObject
)

type ACE struct {
	Header             ACEHeader
	Mask               uint32
	ObjectType         windows.GUID
	SecurityIdentifier windows.SID
}

type ACEHeader struct {
	Type  byte
	Flags byte
	Size  uint16
}

//This is a GUID
type ACEObjectType struct {
	PartA uint32
	PartB uint16
	PartC uint16
	PartD [8]byte
}

func ReadAce(buf *bytes.Buffer) ACE {
	ace := ACE{}
	ace.Header = ReadACEHeader(buf)
	binary.Read(buf, binary.LittleEndian, &ace.Mask)
	ace.ObjectType = ReadGUID(buf)
	ace.SecurityIdentifier = ReadSID(buf)

	return ace
}

func ReadSID(buf *bytes.Buffer) windows.SID {
	data := buf.Next(32)
	sid := (*windows.SID)(unsafe.Pointer(&data))
	return *sid
}

func ReadACEHeader(buf *bytes.Buffer) ACEHeader {
	header := ACEHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Type)
	binary.Read(buf, binary.LittleEndian, &header.Flags)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	return header
}

func ReadGUID(buf *bytes.Buffer) windows.GUID {
	guid := windows.GUID{}
	binary.Read(buf, binary.LittleEndian, &guid.Data1)
	binary.Read(buf, binary.LittleEndian, &guid.Data2)
	binary.Read(buf, binary.LittleEndian, &guid.Data3)
	binary.Read(buf, binary.LittleEndian, &guid.Data4)
	return guid
}
