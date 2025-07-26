package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/flowerinthenight/vortex-agent/internal"
	"github.com/flowerinthenight/vortex-agent/internal/slog"
)

func test() {
	rootPid := internal.GetInitPidNsId()
	if rootPid == -1 {
		slog.Error("invalid init PID namespace")
		return
	}

	files, err := os.ReadDir("/proc")
	if err != nil {
		slog.Error("Failed to read /proc directory:", "err", err)
		return
	}

	for _, f := range files {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue // Not a valid PID, skip
		}

		nspidLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
		if err != nil {
			slog.Error("Failed to read link for PID namespace:", "pid", pid, "err", err)
			continue
		}

		// Format "pid:[<num>]"
		parts := strings.Split(nspidLink, ":")
		if len(parts) < 2 {
			continue
		}

		nspid, err := strconv.Atoi(parts[1][1 : len(parts[1])-1])
		if err != nil {
			continue
		}

		if nspid != rootPid {
			slog.Info("Process not in init PID namespace:", "pid", pid, "nspid", nspid)
			cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if err != nil {
				slog.Error("Failed to read cmdline for PID:", "pid", pid, "err", err)
				return
			}

			// Split by null characters, which separate arguments in /proc/cmdline
			// Filter out empty strings that might result from trailing nulls
			args := bytes.Split(cmdline, []byte{0x00})
			var cleanArgs []string
			for _, arg := range args {
				s := string(arg)
				if s != "" {
					cleanArgs = append(cleanArgs, s)
				}
			}

			slog.Info("jailed:", "pid", pid, "cmdline", strings.Join(cleanArgs, " "))
		}
	}
}
