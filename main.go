//go:build linux

//go:generate sh bpf2go.sh

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/flowerinthenight/vortex-agent/bpf"
	"github.com/flowerinthenight/vortex-agent/internal"
	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Same defs from bpf.c:
const (
	TYPE_UNKNOWN = iota
	TYPE_FENTRY_SOCK_SENDMSG
	TYPE_FEXIT_SOCK_RECVMSG
	TYPE_FEXIT_TCP_SENDMSG
	TYPE_FEXIT_TCP_RECVMSG
	TYPE_FEXIT_UDP_SENDMSG
	TYPE_FEXIT_UDP_RECVMSG
	TYPE_TP_SYS_ENTER_SENDTO
	TYPE_UPROBE_SSL_WRITE
	TYPE_URETPROBE_SSL_WRITE
	TYPE_UPROBE_SSL_READ
	TYPE_URETPROBE_SSL_READ
)

const (
	TGID_ENABLE_ALL = 0xFFFFFFFF
)

var (
	testf = flag.Bool("test", false, "Run in test mode")

	cctx = func(p context.Context) context.Context {
		return context.WithValue(p, struct{}{}, nil)
	}
)

type trafficInfo struct {
	ExtraInfo string
	Ingress   uint64 // bytes received
	Egress    uint64 // bytes sent
}

func main() {
	flag.Parse()
	defer glog.Flush()

	if *testf {
		test()
		return
	}

	sslTestOnly := true

	ctx, cancel := context.WithCancel(context.Background())
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
	glog.Info("BPF objects loaded")

	// ssm, err := link.AttachTracing(link.TracingOptions{
	// 	Program:    objs.SockSendmsgFentry,
	// 	AttachType: ebpf.AttachTraceFEntry,
	// })

	// if err != nil {
	// 	glog.Errorf("fentry/sock_sendmsg failed: %v", err)
	// 	return
	// }

	// defer ssm.Close()
	// glog.Info("fentry/sock_sendmsg attached successfully")

	// srm, err := link.AttachTracing(link.TracingOptions{
	// 	Program:    objs.SockRecvmsgFexit,
	// 	AttachType: ebpf.AttachTraceFExit,
	// })

	// if err != nil {
	// 	glog.Errorf("fexit/sock_recvmsg failed: %v", err)
	// 	return
	// }

	// defer srm.Close()
	// glog.Info("fexit/sock_recvmsg attached successfully")

	tsm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.TcpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/tcp_sendmsg failed: %v", err)
		return
	}

	defer tsm.Close()
	glog.Info("fexit/tcp_sendmsg attached")

	trm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.TcpRecvmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/tcp_recvmsg failed: %v", err)
		return
	}

	defer trm.Close()
	glog.Info("fexit/tcp_recvmsg attached")

	usm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.UdpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/udp_sendmsg failed: %v", err)
		return
	}

	defer usm.Close()
	glog.Info("fexit/udp_sendmsg attached")

	urm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.UdpRecvmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/udp_recvmsg failed: %v", err)
		return
	}

	defer urm.Close()
	glog.Info("fexit/udp_recvmsg attached")

	// kssm, err := link.Kprobe("sock_sendmsg", objs.SockSendmsgEntry, nil)
	// if err != nil {
	// 	slog.Error("kprobe/sock_sendmsg failed:", "err", err)
	// 	return
	// }

	// defer kssm.Close()
	// slog.Info("kprobe/sock_sendmsg attached")

	// tpsnst, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.HandleEnterSendto, nil)
	// if err != nil {
	// 	slog.Error("tracepoint/syscalls/sys_enter_sendto failed:", "err", err)
	// 	return
	// }

	// defer tpsnst.Close()
	// slog.Info("tracepoint/syscalls/sys_enter_sendto attached")

	isk8s := internal.IsK8s()

	if !isk8s {
		libsslPath, err := internal.FindLibSSL("")
		if err != nil {
			glog.Errorf("Error finding libssl.so: %v", err)
			return
		}

		if libsslPath != "" {
			glog.Infof("found libssl at: %s", libsslPath)
			ex, err := link.OpenExecutable(libsslPath)
			if err != nil {
				glog.Errorf("OpenExecutable failed: %v", err)
				return
			}

			upSSLWrite, err := ex.Uprobe("SSL_write", objs.UprobeSSL_write, nil)
			if err != nil {
				glog.Errorf("uprobe/SSL_write failed: %v", err)
				return
			}

			defer upSSLWrite.Close()
			glog.Info("uprobe/SSL_write attached")

			// urpSSLWrite, err := ex.Uretprobe("SSL_write", objs.UretprobeSSL_write, nil)
			// if err != nil {
			// 	glog.Errorf("uretprobe/SSL_write failed: %v", err)
			// 	return
			// }

			// defer urpSSLWrite.Close()
			// glog.Info("uretprobe/SSL_write attached")

			upSSLRead, err := ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
			if err != nil {
				glog.Errorf("uprobe/SSL_read failed: %v", err)
				return
			}

			defer upSSLRead.Close()
			glog.Info("uprobe/SSL_read attached")

			urpSSLRead, err := ex.Uretprobe("SSL_read", objs.UretprobeSSL_read, nil)
			if err != nil {
				glog.Errorf("uretprobe/SSL_read failed: %v", err)
				return
			}

			defer urpSSLRead.Close()
			glog.Info("uretprobe/SSL_read attached")
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		glog.Errorf("ringbuf reader failed: %v", err)
		return
	}

	defer rd.Close()

	go func() {
		<-stopper
		cancel()

		if err := rd.Close(); err != nil {
			glog.Errorf("rd.Close failed: %v", err)
			os.Exit(1)
		}
	}()

	domains := []string{
		"spanner.googleapis.com",
		"bigquery.googleapis.com",
	}

	ipToDomain := make(map[string]string) // key=ip, value=domain
	var ipToDomainMtx sync.Mutex
	ipToDomainCtx := cctx(ctx)

	var wg sync.WaitGroup

	// TODO: This doesn't work properly. Need to figure out another way.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !isk8s {
			return
		}

		ticker := time.NewTicker(time.Second * 10)
		var active atomic.Int32

		do := func() {
			active.Store(1)
			defer active.Store(0)

			for _, domain := range domains {
				ips, err := net.LookupIP(domain)
				if err != nil {
					continue
				}

				func() {
					ipToDomainMtx.Lock()
					defer ipToDomainMtx.Unlock()
					for _, ip := range ips {
						ipToDomain[ip.String()] = domain
					}
				}()
			}
		}

		for {
			select {
			case <-ipToDomainCtx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
			}

			if active.Load() == 1 {
				continue
			}

			go do()
		}
	}()

	podUids := make(map[string]string) // key=pod-uid, value=ns/pod-name
	var podUidsMtx sync.Mutex
	podUidsCtx := cctx(ctx)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if !isk8s {
			return
		}

		config, err := rest.InClusterConfig()
		if err != nil {
			glog.Errorf("InClusterConfig failed: %v", err)
			return
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			glog.Errorf("NewForConfig failed: %v", err)
			return
		}

		ticker := time.NewTicker(time.Second * 10)
		var active atomic.Int32

		do := func() {
			active.Store(1)
			defer active.Store(0)

			pods, err := clientset.CoreV1().Pods("").List(podUidsCtx, metav1.ListOptions{})
			if err != nil {
				glog.Errorf("List pods failed: %v", err)
				return
			}

			for _, pod := range pods.Items {
				if pod.Namespace == "kube-system" {
					continue // skip kube-system namespace
				}

				func() {
					podUidsMtx.Lock()
					defer podUidsMtx.Unlock()
					val := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					podUids[string(pod.ObjectMeta.UID)] = val
				}()
			}
		}

		for {
			select {
			case <-podUidsCtx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
			}

			if active.Load() == 1 {
				continue
			}

			go do()
		}
	}()

	tracedTgids := make(map[uint32]map[string]*trafficInfo) // key=tgid, key(in)=ip
	var tracedTgidsUseMtx atomic.Int32
	var tracedTgidsMtx sync.Mutex
	tracedTgidsCtx := cctx(ctx)

	linksToClose := []link.Link{}
	defer func(list *[]link.Link) {
		for _, l := range *list {
			if err := l.Close(); err != nil {
				glog.Errorf("link.Close failed: %v", err)
			}
		}
	}(&linksToClose)

	wg.Add(1)
	go func(hm *ebpf.Map) {
		defer wg.Done()
		if !isk8s {
			// Enable tracing for all processes if not in k8s.
			err = hm.Put(uint32(TGID_ENABLE_ALL), []byte{1})
			if err != nil {
				glog.Errorf("hm.Put (TGID_ENABLE_ALL) failed: %v", err)
			}

			return
		} else {
			if false {
				return // TODO: test only; remove later
			}
		}

		rootPidNsId := internal.GetInitPidNsId()
		if rootPidNsId == -1 {
			glog.Error("invalid init PID namespace")
			return
		}

		sslAttached := make(map[string]bool) // key=libssl path, value=true

		ticker := time.NewTicker(time.Second * 10)
		var active atomic.Int32

		do := func() {
			active.Store(1)
			defer active.Store(0)

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

				if nspid == rootPidNsId {
					continue // assumed not a container process (host process)
				}

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

				fullCmdline := strings.Join(fargs, " ")
				// glog.Infof("jailed: pid=%d, cmdline=%s", pid, strings.Join(fargs, " "))

				if strings.HasPrefix(fullCmdline, "/pause") {
					continue // skip pause binaries
				}

				// For demo only, skip Alphaus' rmdaily - so many python processes.
				if strings.Contains(fullCmdline, "rmdaily") {
					continue // TODO: remove later
				}

				// For demo only, skip Alphaus' rmdaily - so many python processes.
				if strings.Contains(fullCmdline, "google-cloud-sdk") {
					continue // TODO: remove later
				}

				// ---------------------------------------------
				// TODO: fn is adding to list outside of goroutine!
				func() {
					if true {
						return // TODO: test only; remove later
					}

					rootPath := fmt.Sprintf("/proc/%d/root", pid)
					libsslPath, err := internal.FindLibSSL(rootPath)
					if err != nil {
						return
					}

					if libsslPath == "" {
						return
					}

					if _, ok := sslAttached[rootPath]; ok {
						return // already attached
					}

					sslAttached[rootPath] = true // mark as attached

					glog.Infof("found libssl at: %s", libsslPath)
					ex, err := link.OpenExecutable(libsslPath)
					if err != nil {
						glog.Errorf("OpenExecutable failed: %v", err)
						return
					}

					upSSLWrite, err := ex.Uprobe("SSL_write", objs.UprobeSSL_write, nil)
					if err != nil {
						glog.Errorf("uprobe/SSL_write (%v) failed: %v", libsslPath, err)
						return
					}

					linksToClose = append(linksToClose, upSSLWrite)
					glog.Infof("uprobe/SSL_write attached for %v", libsslPath)

					// urpSSLWrite, err := ex.Uretprobe("SSL_write", objs.UretprobeSSL_write, nil)
					// if err != nil {
					// 	glog.Errorf("uretprobe/SSL_write (%v) failed: %v", libsslPath, err)
					// 	return
					// }

					// linksToClose = append(linksToClose, urpSSLWrite)
					// glog.Infof("uretprobe/SSL_write attached for %v", libsslPath)

					upSSLRead, err := ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
					if err != nil {
						glog.Errorf("uprobe/SSL_read (%v) failed: %v", libsslPath, err)
						return
					}

					linksToClose = append(linksToClose, upSSLRead)
					glog.Infof("uprobe/SSL_read attached for %v", libsslPath)

					urpSSLRead, err := ex.Uretprobe("SSL_read", objs.UretprobeSSL_read, nil)
					if err != nil {
						glog.Errorf("uretprobe/SSL_read (%v) failed: %v", libsslPath, err)
						return
					}

					linksToClose = append(linksToClose, urpSSLRead)
					glog.Infof("uretprobe/SSL_read attached for %v", libsslPath)
				}()
				// ---------------------------------------------

				cgroupb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
				if err != nil {
					glog.Errorf("ReadFile failed: %v", err)
					return
				}

				cgroup := string(cgroupb)
				// glog.Infof("jailed: pid=%d, cgroup=%s", pid, cgroup)

				podUidsClone := func() map[string]string {
					podUidsMtx.Lock()
					defer podUidsMtx.Unlock()
					clone := make(map[string]string, len(podUids))
					maps.Copy(clone, podUids)
					return clone
				}()

				for k, v := range podUidsClone {
					// NOTE: This is a very fragile way of matching cgroups to pods.
					// Tested only on GKE (Alphaus). Need to explore other k8s setups,
					// i.e. EKS, AKS, OpenShift, etc.
					kf := strings.ReplaceAll(k, "-", "_")
					if !strings.Contains(cgroup, kf) {
						continue
					}

					// For demo only, skip Alphaus' rmdaily - so many python processes.
					if strings.Contains(v, "rmdaily") {
						continue // TODO: remove later
					}

					// For demo only, skip Alphaus' rmdaily - so many python processes.
					if strings.Contains(fullCmdline, "google-cloud-sdk") {
						continue // TODO: remove later
					}

					tgid := uint32(pid)
					err = hm.Put(uint32(tgid), []byte{1}) // mark as traced
					if err != nil {
						glog.Errorf("hm.Put failed: %v", err)
						continue
					}

					ipToDomainClone := func() map[string]string {
						ipToDomainMtx.Lock()
						defer ipToDomainMtx.Unlock()
						clone := make(map[string]string, len(ipToDomain))
						maps.Copy(clone, ipToDomain)
						return clone
					}()

					func() {
						tracedTgidsUseMtx.Store(1)
						defer tracedTgidsUseMtx.Store(0)

						val := fmt.Sprintf("%s:%s", v, fullCmdline)
						tracedTgidsMtx.Lock()
						defer tracedTgidsMtx.Unlock()
						if _, ok := tracedTgids[tgid]; !ok {
							tracedTgids[tgid] = make(map[string]*trafficInfo)
							for ip := range ipToDomainClone {
								tracedTgids[tgid][ip] = &trafficInfo{ExtraInfo: val}
							}
						}
					}()
				}
			}
		}

		for {
			select {
			case <-tracedTgidsCtx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
			}

			if active.Load() == 1 {
				continue
			}

			go do()
		}
	}(objs.TgidsToTrace)

	printerCtx := cctx(ctx)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if !isk8s {
			return
		}

		ticker := time.NewTicker(time.Second * 10)
		var active atomic.Int32

		do := func() {
			active.Store(1)
			defer active.Store(0)

			ipToDomainClone := func() map[string]string {
				ipToDomainMtx.Lock()
				defer ipToDomainMtx.Unlock()
				clone := make(map[string]string, len(ipToDomain))
				maps.Copy(clone, ipToDomain)
				return clone
			}()

			tracedTgidsClone := func() map[uint32]map[string]*trafficInfo {
				tracedTgidsUseMtx.Store(1)
				defer tracedTgidsUseMtx.Store(0)

				tracedTgidsMtx.Lock()
				defer tracedTgidsMtx.Unlock()
				clone := make(map[uint32]map[string]*trafficInfo, len(tracedTgids))
				maps.Copy(clone, tracedTgids)
				return clone
			}()

			limit := 100
			for tgid, mip := range tracedTgidsClone {
				var info string
				for ip, ei := range mip {
					if len(ei.ExtraInfo) <= limit {
						info = ei.ExtraInfo
					} else {
						info = ei.ExtraInfo[:limit] + "..."
					}

					ingress := atomic.LoadUint64(&ei.Ingress)
					egress := atomic.LoadUint64(&ei.Egress)
					if (ingress + egress) == 0 {
						continue // skip if no traffic
					}

					glog.Infof("tgid=%d, ip=%v|%v, info=%s, ingress=%d, egress=%d",
						tgid,
						ip,
						ipToDomainClone[ip],
						info,
						ingress,
						egress,
					)
				}
			}

			glog.Infof("%d tgids under trace", len(tracedTgidsClone))
		}

		for {
			select {
			case <-printerCtx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
			}

			if active.Load() == 1 {
				continue
			}

			go do()
		}
	}()

	// var count uint64
	var line strings.Builder
	var event bpf.BpfEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				glog.Info("received signal, exiting...")
				break
			}

			glog.Errorf("reading from reader failed: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			glog.Errorf("parsing ringbuf event failed: %v", err)
			continue
		}

		// count++
		// if count%1000 == 0 {
		// 	glog.Infof("processed %d events", count)
		// }

		line.Reset()

		switch event.Type {
		case TYPE_FENTRY_SOCK_SENDMSG:
			// NOTE: Not used now.

			// fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fentry/sock_sendmsg",
			// 	event.Comm,
			// 	event.Pid,
			// 	event.Tgid,
			// 	intToIP(event.Saddr),
			// 	event.Sport,
			// 	intToIP(event.Daddr),
			// 	event.Dport,
			// 	event.Bytes,
			// )

			// glog.Info(line.String())

		case TYPE_FEXIT_SOCK_RECVMSG:
			// NOTE: Not used now.

			// fmt.Fprintf(&line, "comm=%s, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/sock_recvmsg",
			// 	event.Comm,
			// 	event.Tgid,
			// 	internal.IntToIp(event.Daddr),
			// 	event.Dport,
			// 	internal.IntToIp(event.Saddr),
			// 	event.Sport,
			// 	event.Bytes,
			// )

			// glog.Info(line.String())

		case TYPE_FEXIT_TCP_SENDMSG:
			if strings.HasPrefix(fmt.Sprintf("%s", event.Comm), "sshd") {
				continue
			}

			if !isk8s && !sslTestOnly {
				fmt.Fprintf(&line, "comm=%s, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/tcp_sendmsg",
					event.Comm,
					event.Tgid,
					internal.IntToIp(event.Saddr),
					event.Sport,
					internal.IntToIp(event.Daddr),
					event.Dport,
					event.Bytes,
				)

				glog.Info(line.String())
				continue
			}

			if tracedTgidsUseMtx.Load() == 0 {
				if _, ok := tracedTgids[event.Tgid]; !ok {
					continue
				}

				dstIp := internal.IntToIp(event.Daddr).String()
				if _, ok := tracedTgids[event.Tgid][dstIp]; !ok {
					continue // double check; should be present
				}

				atomic.AddUint64(
					&tracedTgids[event.Tgid][dstIp].Egress,
					uint64(event.Bytes),
				)
			} else {
				func() {
					tracedTgidsMtx.Lock()
					defer tracedTgidsMtx.Unlock()
					if _, ok := tracedTgids[event.Tgid]; !ok {
						return
					}

					dstIp := internal.IntToIp(event.Daddr).String()
					if _, ok := tracedTgids[event.Tgid][dstIp]; !ok {
						return
					}

					atomic.AddUint64(
						&tracedTgids[event.Tgid][dstIp].Egress,
						uint64(event.Bytes),
					)
				}()
			}
		case TYPE_FEXIT_TCP_RECVMSG:
			if !isk8s && !sslTestOnly {
				fmt.Fprintf(&line, "comm=%s, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/tcp_recvmsg",
					event.Comm,
					event.Tgid,
					internal.IntToIp(event.Daddr),
					event.Dport,
					internal.IntToIp(event.Saddr),
					event.Sport,
					event.Bytes,
				)

				glog.Info(line.String())
			}
		case TYPE_FEXIT_UDP_SENDMSG:
			if !isk8s && !sslTestOnly {
				fmt.Fprintf(&line, "comm=%s, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/udp_sendmsg",
					event.Comm,
					event.Tgid,
					internal.IntToIp(event.Saddr),
					event.Sport,
					internal.IntToIp(event.Daddr),
					event.Dport,
					event.Bytes,
				)

				glog.Info(line.String())
			}
		case TYPE_FEXIT_UDP_RECVMSG:
			if !isk8s && !sslTestOnly {
				fmt.Fprintf(&line, "comm=%s, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/udp_recvmsg",
					event.Comm,
					event.Tgid,
					internal.IntToIp(event.Daddr),
					event.Dport,
					internal.IntToIp(event.Saddr),
					event.Sport,
					event.Bytes,
				)

				glog.Info(line.String())
			}
		case TYPE_TP_SYS_ENTER_SENDTO:
			// NOTE: Not used now.
			fmt.Fprintf(&line, "comm=%s, tgid=%v, ret=%v, fn=sys_enter_sendto",
				event.Comm,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case TYPE_UPROBE_SSL_WRITE:
			fmt.Fprintf(&line, "comm=%s, buf=%s, tgid=%v, ret=%v, fn=uprobe/SSL_write",
				event.Comm,
				event.Buf,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case TYPE_URETPROBE_SSL_WRITE:
			fmt.Fprintf(&line, "comm=%s, buf=%s, tgid=%v, ret=%v, fn=uretprobe/SSL_write",
				event.Comm,
				event.Buf,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case TYPE_UPROBE_SSL_READ:
			fmt.Fprintf(&line, "comm=%s, buf=%s, tgid=%v, ret=%v, fn=uprobe/SSL_read",
				event.Comm,
				event.Buf,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case TYPE_URETPROBE_SSL_READ:
			fmt.Fprintf(&line, "comm=%s, buf=%s, tgid=%v, ret=%v, fn=uretprobe/SSL_read",
				event.Comm,
				event.Buf,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		default:
		}
	}

	wg.Wait()
}
