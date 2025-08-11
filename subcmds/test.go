package subcmds

import (
	"bufio"
	"container/list"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flowerinthenight/vortex-agent/internal/slog"
	"github.com/spf13/cobra"
)

func TestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test anything, throw-away code",
		Long:  `Test anything, throw-away code.`,
		Run: func(cmd *cobra.Command, args []string) {
			if true {
				testListAsStack()
				return
			}

			if true {
				a := []int{}
				defer func(l *[]int) {
					for i, v := range *l {
						slog.Info("defer called", "index", i, "value", v)
					}
				}(&a)

				a = append(a, 1, 2, 3)
				return
			}

			if false {
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

			// rootPid := internal.GetInitPidNsId()
			// if rootPid == -1 {
			// 	slog.Error("invalid init PID namespace")
			// 	return
			// }

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

				func() {
					filePath := fmt.Sprintf("/proc/%d/maps", pid)
					file, err := os.Open(filePath)
					if err != nil {
						slog.Error("Open failed:", "pid", pid, "err", err)
						return
					}

					defer file.Close()
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := scanner.Text()
						parts := strings.Fields(line)

						if len(parts) >= 6 {
							addressRange := parts[0]
							permissions := parts[1]
							offset := parts[2]
							deviceName := parts[3]
							inode, _ := strconv.Atoi(parts[4])
							path := ""
							if len(parts) > 5 {
								path = strings.Join(parts[5:], " ")
							}

							if strings.Contains(path, "libssl.so") {
								slog.Info("map:",
									"pid", pid,
									"addressRange", addressRange,
									"permissions", permissions,
									"offset", offset,
									"deviceName", deviceName,
									"inode", inode,
									"path", path,
								)
							}
						}
					}

					if err := scanner.Err(); err != nil {
						slog.Error("Error reading file:", "pid", pid, "err", err)
					}
				}()

				// nspidLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
				// if err != nil {
				// 	slog.Error("Failed to read link for PID namespace:", "pid", pid, "err", err)
				// 	continue
				// }

				// // Format "pid:[<num>]"
				// parts := strings.Split(nspidLink, ":")
				// if len(parts) < 2 {
				// 	continue
				// }

				// nspid, err := strconv.Atoi(parts[1][1 : len(parts[1])-1])
				// if err != nil {
				// 	continue
				// }

				// if nspid != rootPid {
				// 	slog.Info("Process not in init PID namespace:", "pid", pid, "nspid", nspid)
				// 	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				// 	if err != nil {
				// 		slog.Error("Failed to read cmdline for PID:", "pid", pid, "err", err)
				// 		return
				// 	}

				// 	// Split by null characters, which separate arguments in /proc/cmdline
				// 	// Filter out empty strings that might result from trailing nulls
				// 	args := bytes.Split(cmdline, []byte{0x00})
				// 	var cleanArgs []string
				// 	for _, arg := range args {
				// 		s := string(arg)
				// 		if s != "" {
				// 			cleanArgs = append(cleanArgs, s)
				// 		}
				// 	}

				// 	slog.Info("jailed:", "pid", pid, "cmdline", strings.Join(cleanArgs, " "))
				// }

				// cgroupb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
				// if err != nil {
				// 	slog.Error("ReadFile failed:", "pid", pid, "err", err)
				// 	return
				// }

				// cgroup := string(cgroupb)
				// slog.Info("cgroup for PID", "pid", pid, "cgroup", cgroup)
			}
		},
	}

	cmd.Flags().SortFlags = false
	return cmd
}

func testListAsStack() {
	ll := list.New()
	ll.PushBack(1)
	ll.PushBack(2)
	ll.PushBack(3)
	v := ll.Remove(ll.Back())
	slog.Info("Popped value from stack", "value", v)
	v = ll.Remove(ll.Back())
	slog.Info("Popped value from stack", "value", v)
	v = ll.Remove(ll.Back())
	slog.Info("Popped value from stack", "value", v)
	slog.Info("Stack is empty now", "length", ll.Len())
}
