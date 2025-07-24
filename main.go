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
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/flowerinthenight/vortex-agent/bpf"
	"github.com/golang/glog"
)

func main() {
	flag.Parse()
	defer glog.Flush()
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

	// For test only; hardcoded path to libssl.so.3.
	ex, err := link.OpenExecutable("/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		glog.Errorf("Failed to open executable: %v", err)
		return
	}

	upSSLWrite, err := ex.Uprobe("SSL_write", objs.UprobeSSL_write, nil)
	if err != nil {
		glog.Errorf("Failed to attach uprobe to SSL_write: %v", err)
		return
	}

	defer upSSLWrite.Close()
	glog.Info("uprobe to SSL_write attached successfully")

	upSSLRead, err := ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
	if err != nil {
		glog.Errorf("Failed to attach uprobe to SSL_read: %v", err)
		return
	}

	defer upSSLRead.Close()
	glog.Info("uprobe to SSL_read attached successfully")

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
		case 7:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=SSL_read",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 6:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, fn=SSL_write",
				event.Comm,
				event.Pid,
				event.Tgid,
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

			// glog.Info(line.String())
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

			// glog.Info(line.String())
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

			// glog.Info(line.String())
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
