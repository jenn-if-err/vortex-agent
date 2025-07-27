package internal

import (
	"encoding/binary"
	"net"
	"unsafe"
)

// IsLE checks the endianness of the system
// and logs whether it is little-endian (LE)
// or big-endian (BE).
func IsLE() bool {
	var i int32 = 1
	b := (*[4]byte)(unsafe.Pointer(&i))
	switch b[0] {
	case 1:
		return true
	default:
		return false
	}
}

func IntToIp(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}
