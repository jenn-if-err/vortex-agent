package internal

import (
	"os"
	"strconv"
	"strings"
)

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
