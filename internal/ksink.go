package internal

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
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

func GetInitPidNsId() int {
	nspidLink, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return -1
	}

	// Format "pid:[<num>]"
	parts := strings.Split(nspidLink, ":")
	if len(parts) < 2 {
		return -1
	}

	pid, err := strconv.Atoi(parts[1][1 : len(parts[1])-1])
	if err != nil {
		return -1
	}

	return pid
}

func IsK8s() bool {
	_, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	return exists
}

func FindLibSSL() (string, error) {
	possiblePaths := []string{
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3", // for OpenSSL 3.x
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/local/lib/libssl.so", // custom installations
		"/lib64/libssl.so",         // RHEL/CentOS
	}

	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("libssl.so not found")
}
