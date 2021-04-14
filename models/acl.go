package models

type ACL struct {
	Header ACLHeader
	Aces   []ACE
}

type ACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}
