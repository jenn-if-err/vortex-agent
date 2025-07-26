//go:build linux

//go:generate sh bpf2go.sh

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/flowerinthenight/vortex-agent/bpf"
	"github.com/golang/glog"
)

var (
	testf = flag.Bool("test", false, "Run in test mode")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	if *testf {
		test()
		return
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		glog.Errorf("RemoveMemlock failed: %v", err)
		return
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		glog.Errorf("loadBpfObjects failed: %v", err)
		return
	}

	defer objs.Close()
	glog.Info("BPF objects loaded successfully")

	ssm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.SockSendmsgFentry,
		AttachType: ebpf.AttachTraceFEntry,
	})

	if err != nil {
		glog.Errorf("fentry/sock_sendmsg failed: %v", err)
		return
	}

	defer ssm.Close()
	glog.Info("fentry/sock_sendmsg attached successfully")

	srm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.SockRecvmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/sock_recvmsg failed: %v", err)
		return
	}

	defer srm.Close()
	glog.Info("fexit/sock_recvmsg attached successfully")

	tsm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.TcpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/tcp_sendmsg failed: %v", err)
		return
	}

	defer tsm.Close()
	glog.Info("fexit/tcp_sendmsg attached successfully")

	usm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.UdpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/udp_sendmsg failed: %v", err)
		return
	}

	defer usm.Close()
	glog.Info("fexit/udp_sendmsg attached successfully")

	// kssm, err := link.Kprobe("sock_sendmsg", objs.SockSendmsgEntry, nil)
	// if err != nil {
	// 	slog.Error("kprobe/sock_sendmsg failed:", "err", err)
	// 	return
	// }

	// defer kssm.Close()
	// slog.Info("kprobe/sock_sendmsg attached successfully")

	// tpsnst, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.HandleEnterSendto, nil)
	// if err != nil {
	// 	slog.Error("tracepoint/syscalls/sys_enter_sendto failed:", "err", err)
	// 	return
	// }

	// defer tpsnst.Close()
	// slog.Info("tracepoint/syscalls/sys_enter_sendto attached successfully")

	libsslPath, err := findLibSSL()
	if err != nil {
		glog.Errorf("Error finding libssl.so: %v", err)
		return
	}

	if libsslPath != "" {
		ex, err := link.OpenExecutable(libsslPath)
		if err != nil {
			glog.Errorf("OpenExecutable failed: %v", err)
			return
		}

		upSSLWrite, err := ex.Uprobe("SSL_write", objs.UprobeSSL_write, nil)
		if err != nil {
			glog.Errorf("Uprobe (uprobe/SSL_write) failed: %v", err)
			return
		}

		defer upSSLWrite.Close()
		glog.Info("uprobe/SSL_write attached successfully")

		urpSSLWrite, err := ex.Uretprobe("SSL_write", objs.UretprobeSSL_write, nil)
		if err != nil {
			glog.Errorf("Uretprobe (uretprobe/SSL_write) failed: %v", err)
			return
		}

		defer urpSSLWrite.Close()
		glog.Info("uretprobe/SSL_write attached successfully")

		upSSLRead, err := ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
		if err != nil {
			glog.Errorf("Uprobe (uprobe/SSL_read) failed: %v", err)
			return
		}

		defer upSSLRead.Close()
		glog.Info("uprobe/SSL_read attached successfully")

		urpSSLRead, err := ex.Uretprobe("SSL_read", objs.UretprobeSSL_read, nil)
		if err != nil {
			glog.Errorf("Uretprobe (uretprobe/SSL_read) failed: %v", err)
			return
		}

		defer urpSSLRead.Close()
		glog.Info("uretprobe/SSL_read attached successfully")
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		glog.Errorf("ringbuf reader failed: %v", err)
		return
	}

	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			glog.Errorf("rd.Close failed: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		rootPid := getInitNsPid()
		if rootPid == -1 {
			glog.Error("invalid init PID namespace")
			return
		}

		for {
			files, err := os.ReadDir("/proc")
			if err != nil {
				glog.Errorf("ReadDir /proc failed: %v", err)
				return
			}

			for _, f := range files {
				pid, err := strconv.Atoi(f.Name())
				if err != nil {
					continue
				}

				nspidLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
				if err != nil {
					glog.Errorf("Readlink failed: %v", err)
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
					cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					if err != nil {
						glog.Errorf("ReadFile failed: %v", err)
						return
					}

					args := bytes.Split(cmdline, []byte{0x00})
					var fargs []string
					for _, arg := range args {
						s := string(arg)
						if s != "" {
							fargs = append(fargs, s)
						}
					}

					glog.Infof("jailed: pid=%d, cmdline=%s", pid, strings.Join(fargs, " "))
				}
			}

			time.Sleep(10 * time.Second)
		}
	}()

	var count uint64
	var line strings.Builder
	var event bpf.BpfEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				glog.Info("received signal, exiting...")
				return
			}

			glog.Errorf("reading from reader failed: %v", err)
			continue
		}

		count++
		if count%1000 == 0 {
			glog.Infof("count: %d", count)
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			glog.Errorf("parsing ringbuf event failed: %v", err)
			continue
		}

		line.Reset()

		switch event.Type {
		case 9:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uretprobe/SSL_read",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 8:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uprobe/SSL_read",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 7:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uretprobe/SSL_write",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 6:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uprobe/SSL_write",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 5:
			// NOTE: Not used now.
			fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, ret=%v, fn=sys_enter_sendto",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 4:
			fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/udp_sendmsg",
				event.Comm,
				event.Pid,
				event.Tgid,
				intToIP(event.Saddr),
				event.Sport,
				intToIP(event.Daddr),
				event.Dport,
				event.Bytes,
			)

			glog.Info(line.String())
		case 3:
			if strings.HasPrefix(fmt.Sprintf("%s", event.Comm), "sshd") {
				continue
			}

			fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/tcp_sendmsg",
				event.Comm,
				event.Pid,
				event.Tgid,
				intToIP(event.Saddr),
				event.Sport,
				intToIP(event.Daddr),
				event.Dport,
				event.Bytes,
			)

			glog.Info(line.String())
		case 2:
			fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/sock_recvmsg",
				event.Comm,
				event.Pid,
				event.Tgid,
				intToIP(event.Daddr),
				event.Dport,
				intToIP(event.Saddr),
				event.Sport,
				event.Bytes,
			)

			glog.Info(line.String())
		case 1:
			fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fentry/sock_sendmsg",
				event.Comm,
				event.Pid,
				event.Tgid,
				intToIP(event.Saddr),
				event.Sport,
				intToIP(event.Daddr),
				event.Dport,
				event.Bytes,
			)

			glog.Info(line.String())
		default:
		}
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// findLibSSL attempts to locate libssl.so
func findLibSSL() (string, error) {
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
			glog.Infof("found libssl at: %s", p)
			return p, nil
		}
	}

	return "", fmt.Errorf("libssl.so not found")
}

func getInitNsPid() int {
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
