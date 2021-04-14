package parsers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/rvazarkar/go-winacl/models"
	"golang.org/x/sys/windows"
)

func ReadGUID(buf *bytes.Buffer) windows.GUID {
	guid := windows.GUID{}
	binary.Read(buf, binary.LittleEndian, &guid.Data1)
	binary.Read(buf, binary.LittleEndian, &guid.Data2)
	binary.Read(buf, binary.LittleEndian, &guid.Data3)
	binary.Read(buf, binary.LittleEndian, &guid.Data4)
	return guid
}

func ReadSID(buf *bytes.Buffer, sidLength int) (models.SID, error) {
	sid := models.SID{}
	data := buf.Next(sidLength)

	if revision := data[0]; revision != 1 {
		return sid, errors.New("invalid SID revision")
	} else if numAuth := data[1]; numAuth > 15 {
		return sid, errors.New("invalid number of subauthorities")
	} else if ((int(numAuth) * 4) + 8) < len(data) {
		return sid, errors.New("invalid sid length")
	} else {
		authority := data[2:8]
		subAuth := make([]uint32, numAuth)
		for i := 0; i < int(numAuth); i++ {
			offset := 8 + (i * 4)
			subAuth[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
		}

		sid.Revision = revision
		sid.Authority = authority
		sid.NumAuthorities = numAuth
		sid.SubAuthorities = subAuth

		return sid, nil
	}

}
