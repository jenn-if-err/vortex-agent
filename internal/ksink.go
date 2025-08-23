package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func ChildCtx(p context.Context) context.Context {
	return context.WithValue(p, struct{}{}, nil)
}

func Uname() string {
	cmd := exec.Command("uname", "-a")
	output, _ := cmd.CombinedOutput()
	return strings.TrimRight(string(output), "\n")
}

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

func IpToInt(ip net.IP) uint32 {
	ip4 := ip.To4()
	switch ip4 {
	case nil:
		return 0
	default:
		return binary.LittleEndian.Uint32(ip4)
	}
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

func GetSelfRootPid() int {
	me, err := os.Readlink("/proc/self")
	if err != nil {
		return -1
	}

	pid, err := strconv.Atoi(me)
	if err != nil {
		return -1
	}

	return pid
}

func FindCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"
	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}

	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}

	return cgroupPath, nil
}

func IsK8s() bool {
	_, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	return exists
}

func FindLibSSL(root string) (string, error) {
	possiblePaths := []string{
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3", // for OpenSSL 3.x
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/local/lib/libssl.so", // custom installations
		"/lib64/libssl.so",         // RHEL/CentOS
	}

	for _, p := range possiblePaths {
		path := fmt.Sprintf("%s%s", root, p)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("libssl.so not found")
}

func FindHomebrewSSL(root string) []string {
	path := fmt.Sprintf("%s/home/linuxbrew/.linuxbrew/Cellar/openssl@3", root)
	foundFiles := []string{}
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && strings.HasPrefix(info.Name(), "libssl.so.") {
			foundFiles = append(foundFiles, path)
		}

		return nil
	})

	return foundFiles
}

func FindNodeBin(root string) (string, error) {
	possiblePaths := []string{
		"/usr/bin/node",
		"/usr/local/bin/node",
		"/bin/node",
	}

	for _, p := range possiblePaths {
		path := fmt.Sprintf("%s%s", root, p)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("node binary not found")
}

// For debugging SSL buffers.
func Readable(s []byte, len int64) string {
	var b strings.Builder
	for i, c := range s {
		if len > 0 && int64(i) >= len {
			break // respect the length limit
		}

		if c == '\x00' {
			b.WriteByte('.')
			continue // replace null bytes with a dot
		}

		if (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t' {
			b.WriteByte(c)
		}
	}

	return b.String()
}
