package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flowerinthenight/vortex-agent/internal"
	"github.com/flowerinthenight/vortex-agent/internal/slog"
)

func test() {
	if true {
		type vT struct {
			a int
			b uint64
		}

		m := make(map[int]map[int]*vT)
		m[0] = make(map[int]*vT)
		m[0][1] = &vT{}

		var x sync.Mutex
		var w sync.WaitGroup
		var useLock atomic.Int32
		var ulcnt uint64

		w.Add(1)
		go func() {
			defer w.Done()
			for i := range []int{1, 2, 3, 4, 5} {
				func() {
					useLock.Store(1)
					defer useLock.Store(0)

					x.Lock()
					defer x.Unlock()
					m[i] = make(map[int]*vT)
					m[i][1] = &vT{}
				}()

				time.Sleep(5 * time.Second)
			}
		}()

		start := time.Now()

		w.Add(1)
		go func() {
			defer w.Done()
			for range 3_000_000_000 {
				var print bool
				if useLock.Load() == 0 {
					atomic.AddUint64(&m[0][1].b, 1)
					print = false
				} else {
					if !print {
						slog.Info("useLock is set, locking")
						print = true
					}

					func() {
						x.Lock()
						defer x.Unlock()
						atomic.AddUint64(&m[0][1].b, 1)
						atomic.AddUint64(&ulcnt, 1)
					}()
				}
			}
		}()

		w.Wait()
		slog.Info("test completed:", "m", m, "lockCount", ulcnt, "duration", time.Since(start))
		return
	}

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
