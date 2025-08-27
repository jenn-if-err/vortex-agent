//go:build linux

package subcmds

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/flowerinthenight/vortex-agent/bpf"
	"github.com/flowerinthenight/vortex-agent/internal"
	internalglog "github.com/flowerinthenight/vortex-agent/internal/glog"
	"github.com/flowerinthenight/vortex-agent/params"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Same defs from {root}/bpf/vortex.h:
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
	TYPE_REPORT_WRITE_SOCKET_INFO
	TYPE_UPROBE_SSL_READ
	TYPE_URETPROBE_SSL_READ
	TYPE_REPORT_READ_SOCKET_INFO
	TYPE_ANY = 255
)

const (
	TGID_ENABLE_ALL = 0xFFFFFFFF
)

// https://datatracker.ietf.org/doc/html/rfc7540#section-11.2
const (
	FrameData         uint8 = 0x0
	FrameHeaders      uint8 = 0x1
	FramePriority     uint8 = 0x2
	FrameRstStream    uint8 = 0x3
	FrameSettings     uint8 = 0x4
	FramePushPromise  uint8 = 0x5
	FramePing         uint8 = 0x6
	FrameGoAway       uint8 = 0x7
	FrameWindowUpdate uint8 = 0x8
	FrameContinuation uint8 = 0x9
)

const (
	FlagPadded uint8 = 0x8
)

const (
	CHUNK_END_IDX = 0xFFFFFFFF
)

type trafficInfo struct {
	ExtraInfo string
	Ingress   uint64 // bytes received
	Egress    uint64 // bytes sent
}

type eventStateT struct {
	http2 atomic.Int32 // 0: not http2, 1: http2
}

type ContainerInfo struct {
	Name   string
	Image  string
	PodUId string
}

type responseBucket struct {
	chunks     [][]byte
	chunkOrder []int     // track the order of chunks based on idx
	received   int
	total      int
	lastUpdate time.Time
}

func RunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run as agent (long running)",
		Long:  `Run as agent (long running).`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error)

			go run(ctx, done)

			go func() {
				sigch := make(chan os.Signal, 1)
				signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
				<-sigch
				cancel()
			}()

			<-done
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVar(&params.RunfUprobes, "uprobes", "", "Lib/bin files to attach to uprobes (comma-separated)")
	cmd.Flags().BoolVar(&params.RunfSaveDb, "savedb", false, "If set to true, save data to Spanner")
	cmd.Flags().BoolVar(&params.RunfDisableLogs, "nologs", false, "If set to true, disable logs (for performance)")
	return cmd
}

func run(ctx context.Context, done chan error) {
	defer func() { done <- nil }()

	glog.Infof("Running on [%v]", internal.Uname())

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
	internalglog.LogInfo("BPF objects loaded")

	hostLinks := []link.Link{}
	defer func(list *[]link.Link) {
		for _, l := range *list {
			if err := l.Close(); err != nil {
				glog.Errorf("link.Close failed: %v", err)
			}
		}
	}(&hostLinks)

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.TcpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/tcp_sendmsg failed: %v", err)
	} else {
		hostLinks = append(hostLinks, l)
	}

	l, err = link.AttachTracing(link.TracingOptions{
		Program:    objs.TcpRecvmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/tcp_recvmsg failed: %v", err)
	} else {
		hostLinks = append(hostLinks, l)
	}

	// kssm, err := link.Kprobe("sock_sendmsg", objs.SockSendmsgEntry, nil)
	// if err != nil {
	// 	slog.Error("kprobe/sock_sendmsg failed:", "err", err)
	// 	return
	// }

	// defer kssm.Close()
	// slog.LogInfo("kprobe/sock_sendmsg attached")

	l, err = link.Tracepoint("syscalls", "sys_enter_connect", objs.SysEnterConnect, nil)
	if err != nil {
		glog.Errorf("tp/syscalls/sys_enter_connect failed: %v", err)
	} else {
		hostLinks = append(hostLinks, l)
	}

	l, err = link.Tracepoint("sock", "inet_sock_set_state", objs.InetSockSetState, nil)
	if err != nil {
		glog.Errorf("tp/sock/inet_sock_set_state failed: %v", err)
	} else {
		hostLinks = append(hostLinks, l)
	}

	func() {
		interfaces, err := net.Interfaces()
		if err != nil {
			glog.Errorf("Error getting network interfaces: %v", err)
			return
		}

		glog.Info("available network interfaces:")
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 {
				continue
			}

			glog.Infof("interface: name=%s, mtu=%d, flags=%s", iface.Name, iface.MTU, iface.Flags.String())

			iface, err := net.InterfaceByName(iface.Name)
			if err != nil {
				glog.Errorf("lookup network iface %q: %s", iface.Name, err)
			} else {
				le, err := link.AttachTCX(link.TCXOptions{
					Interface: iface.Index,
					Program:   objs.TcEgress,
					Attach:    ebpf.AttachTCXEgress,
				})

				if err != nil {
					glog.Errorf("attach tc_egress to iface %q failed: %v", iface.Name, err)
				} else {
					hostLinks = append(hostLinks, le)
				}

				li, err := link.AttachTCX(link.TCXOptions{
					Interface: iface.Index,
					Program:   objs.TcIngress,
					Attach:    ebpf.AttachTCXIngress,
				})

				if err != nil {
					glog.Errorf("attach tc_ingress to iface %q failed: %v", iface.Name, err)
				} else {
					hostLinks = append(hostLinks, li)
				}
			}
		}
	}()

	cgroupPath, err := internal.FindCgroupPath()
	if err != nil {
		glog.Errorf("FindCgroupPath failed: %v", err)
	} else {
		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: objs.CgroupConnect4,
		})

		if err != nil {
			glog.Errorf("attaching cgroup/connect4 to %v failed: %v", cgroupPath, err)
		} else {
			hostLinks = append(hostLinks, l)
		}

		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCgroupInetSockRelease,
			Program: objs.CgroupSockRelease,
		})

		if err != nil {
			glog.Errorf("attaching cgroup/sock_release to %v failed: %v", cgroupPath, err)
		} else {
			hostLinks = append(hostLinks, l)
		}
	}

	isk8s := internal.IsK8s()
	uprobeFiles := strings.Split(params.RunfUprobes, ",")

	if !isk8s {
		libsslPath, _ := internal.FindLibSSL("")
		uprobeFiles = append(uprobeFiles, libsslPath)
		uprobeFiles = append(uprobeFiles, internal.FindHomebrewSSL("")...)
		for _, uf := range uprobeFiles {
			if uf == "" {
				continue
			}

			ex, err := link.OpenExecutable(uf)
			if err != nil {
				glog.Errorf("OpenExecutable failed: %v", err)
				return
			}

			glog.Infof("attaching u[ret]probes to [%s]", uf)

			setupUprobes(ex, &hostLinks, &objs)
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		glog.Errorf("ringbuf reader failed: %v", err)
		return
	}

	defer rd.Close()

	go func() {
		<-ctx.Done()

		if err := rd.Close(); err != nil {
			glog.Errorf("rd.Close failed: %v", err)
			os.Exit(1)
		}
	}()

	domains := []string{
		"spanner.googleapis.com",
		"bigquery.googleapis.com",
		"generativelanguage.googleapis.com",
		"api.openai.com",
	}

	ipToDomain := make(map[string]string) // key=ip, value=domain
	var ipToDomainMtx sync.Mutex
	ipToDomainCtx := internal.ChildCtx(ctx)

	var wg sync.WaitGroup
	var globalMessageID uint64 // unique message ID for each event
	var responseMap sync.Map   // key: respKey, value: *responseBucket

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
	ipToContainer := make(map[string]*ContainerInfo)
	var ipToContainerMtx sync.Mutex
	var podUidsMtx sync.Mutex
	podUidsCtx := internal.ChildCtx(ctx)

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

				for _, container := range pod.Spec.Containers {
					info := ContainerInfo{
						Name:   container.Name,
						Image:  container.Image,
						PodUId: string(pod.ObjectMeta.UID),
					}

					func() {
						ipToContainerMtx.Lock()
						defer ipToContainerMtx.Unlock()
						glog.Infof("ip=%v, container=%+v", pod.Status.PodIP, info)
						ipToContainer[pod.Status.PodIP] = &info
					}()
				}

				func() {
					podUidsMtx.Lock()
					defer podUidsMtx.Unlock()
					val := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					podUids[string(pod.ObjectMeta.UID)] = val
				}()
			}
		}

		go do() // first
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
	tracedTgidsCtx := internal.ChildCtx(ctx)

	cgroupLinks := []link.Link{}
	defer func(list *[]link.Link) {
		for _, l := range *list {
			if err := l.Close(); err != nil {
				glog.Errorf("link.Close failed: %v", err)
			}
		}
	}(&cgroupLinks)

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

		pidSelf := internal.GetSelfRootPid()
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

			// NOTE:
			// Methods for accessing container-based file systems for u[ret]probes.
			//
			// 1) Check /proc/pid/root/. Symbolic link to pid's root directory.
			//    Recommended method.
			//
			// 2) Check /proc/pid/mountinfo. There will be a lowerdir, upperdir, and
			//    workdir mounts. Replace upperdir's ---/diff/ to ---/merged/.

			for _, f := range files {
				pid, err := strconv.Atoi(f.Name())
				if err != nil {
					continue
				}

				if pidSelf > 1 && pid == pidSelf {
					glog.Infof("skipping self, pid=%d", pid)
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
					continue
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
				// internalglog.LogInfof("jailed: pid=%d, cmdline=%s", pid, strings.Join(fargs, " "))

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

				func() {
					var libs []string
					rootPath := fmt.Sprintf("/proc/%d/root", pid)
					libsslPath, _ := internal.FindLibSSL(rootPath)
					libs = append(libs, libsslPath)
					libs = append(libs, internal.FindHomebrewSSL(rootPath)...)

					nodeBinPath, _ := internal.FindNodeBin(rootPath)
					libs = append(libs, nodeBinPath)
					for _, lib := range libs {
						if lib == "" {
							continue
						}

						if _, ok := sslAttached[lib]; ok {
							continue
						}

						sslAttached[lib] = true // mark as attached

						internalglog.LogInfof("found lib/bin at: %s, pid=%v", lib, pid)
						ex, err := link.OpenExecutable(lib)
						if err != nil {
							glog.Errorf("OpenExecutable failed: %v", err)
							continue
						}

						setupUprobes(ex, &cgroupLinks, &objs)
					}
				}()

				cgroupb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
				if err != nil {
					glog.Errorf("ReadFile failed: %v", err)
					continue
				}

				cgroup := string(cgroupb)
				// internalglog.LogInfof("jailed: pid=%d, cgroup=%s", pid, cgroup)

				podUidsClone := func() map[string]string {
					podUidsMtx.Lock()
					defer podUidsMtx.Unlock()
					clone := make(map[string]string, len(podUids))
					maps.Copy(clone, podUids)
					return clone
				}()

				for k, v := range podUidsClone {
					// NOTE:
					// This is a very fragile way of matching cgroups to pods.
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

	printerCtx := internal.ChildCtx(ctx)

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

					internalglog.LogInfof("tgid=%d, ip=%v|%v, info=%s, ingress=%d, egress=%d",
						tgid,
						ip,
						ipToDomainClone[ip],
						info,
						ingress,
						egress,
					)
				}
			}

			internalglog.LogInfof("%d tgids under trace", len(tracedTgidsClone))
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

	mutBuf := make([]internal.SpannerPayload, 0, 4096)
	mutBufCh := make(chan internal.SpannerPayload, 8192)

	flush := func() {
		if len(mutBuf) == 0 {
			return
		}
		err := internal.Send("", mutBuf)
		if err != nil {
			glog.Errorf("failed to send vortex spanner request: %v", err)
		} else {
			internalglog.LogInfof("saved %d event(s) to db", true, len(mutBuf))
		}
		mutBuf = mutBuf[:0]
	}

	tickerFlush := time.NewTicker(5 * time.Second)
	defer tickerFlush.Stop()
	
	// Cleanup stale response buckets
	tickerCleanup := time.NewTicker(30 * time.Second)
	defer tickerCleanup.Stop()
	
	go func() {
		for range tickerCleanup.C {
			now := time.Now()
			responseMap.Range(func(key, value interface{}) bool {
				bucket := value.(*responseBucket)
				if now.Sub(bucket.lastUpdate) > 60*time.Second {
					internalglog.LogInfof("llm_response: cleaning up stale bucket for key %v", key)
					responseMap.Delete(key)
				}
				return true
			})
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case s, ok := <-mutBufCh:
				if !ok {
					flush()
					return
				}
				mutBuf = append(mutBuf, s)
				if len(mutBuf) >= 4096 {
					flush()
				}
			case <-tickerFlush.C:
				flush()
			}
		}
	}()

	eventState := make(map[string]*eventStateT)
	eventSink := make(chan bpf.BpfEvent, 2048) // what size to use?

	for i := range runtime.NumCPU() {
		wg.Add(1)
		go func(id int) {
			defer func() {
				wg.Done()
			}()
			var line strings.Builder
			// NOTE: All logs/prints here are for debugging purposes only.
			// They need to be removed in production code as they have
			// a significant performance impact.

			for event := range eventSink {
				line.Reset()
				key := fmt.Sprintf("%v/%v", event.Tgid, event.Pid)
				switch event.Type {
				case TYPE_FENTRY_SOCK_SENDMSG:

				case TYPE_FEXIT_SOCK_RECVMSG:

				case TYPE_FEXIT_TCP_SENDMSG:
					if strings.HasPrefix(fmt.Sprintf("%s", event.Comm), "sshd") {
						continue
					}

					if !isk8s {
						if !strings.HasPrefix(fmt.Sprintf("%s", event.Comm), "node") {
							continue
						}

						fmt.Fprintf(&line, "[fexit/tcp_sendmsg] comm=%s, key=%v, ", event.Comm, key)
						fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Saddr), event.Sport)
						fmt.Fprintf(&line, "dst=%v:%v, ", internal.IntToIp(event.Daddr), event.Dport)
						fmt.Fprintf(&line, "len=%v", event.TotalLen)
						internalglog.LogInfo(line.String())
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
							uint64(event.TotalLen),
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
								uint64(event.TotalLen),
							)
						}()
					}

				case TYPE_FEXIT_TCP_RECVMSG:
					if !isk8s {
						if !strings.HasPrefix(fmt.Sprintf("%s", event.Comm), "node") {
							continue
						}

						fmt.Fprintf(&line, "[fexit/tcp_recvmsg] comm=%s, key=%v, ", event.Comm, key)
						fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Daddr), event.Dport)
						fmt.Fprintf(&line, "dst=%v:%v, ", internal.IntToIp(event.Saddr), event.Sport)
						fmt.Fprintf(&line, "len=%v", event.TotalLen)
						internalglog.LogInfo(line.String())
					}

				case TYPE_FEXIT_UDP_SENDMSG:

				case TYPE_FEXIT_UDP_RECVMSG:

				case TYPE_TP_SYS_ENTER_SENDTO:

				case TYPE_UPROBE_SSL_WRITE:

				case TYPE_URETPROBE_SSL_WRITE:
					fmt.Fprintf(&line, "[uretprobe/SSL_write{_ex}] idx=%v, ", event.ChunkIdx)
					fmt.Fprintf(&line, "buf=%s, ", internal.Readable(event.Buf[:], max(event.ChunkLen, 0)))
					fmt.Fprintf(&line, "key=%v, totalLen=%v, chunkLen=%v, ", key, event.TotalLen, event.ChunkLen)
					fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Saddr), event.Sport)
					fmt.Fprintf(&line, "dst=%v:%v ", internal.IntToIp(event.Daddr), event.Dport)
					var containerName, containerImage string
					func() {
						if !isk8s {
							return
						}
						ipToContainerMtx.Lock()
						defer ipToContainerMtx.Unlock()
						info, ok := ipToContainer[internal.IntToIp(event.Saddr).String()]
						if ok {
							containerName = info.Name
							containerImage = info.Image
							fmt.Fprintf(&line, "srcContainerName=%v ", info.Name)
						}
					}()

					func() {
						if !isk8s {
							return
						}
						ipToDomainMtx.Lock()
						defer ipToDomainMtx.Unlock()
						info, ok := ipToDomain[internal.IntToIp(event.Daddr).String()]
						if ok {
							fmt.Fprintf(&line, "targetDomain=%v ", info)
						}
					}()
					internalglog.LogInfo(line.String())

					if strings.Contains(fmt.Sprintf("%s", event.Comm), "node") || (strings.Contains(fmt.Sprintf("%s", event.Comm), "python")) && params.RunfSaveDb {
						cols := []string{
							"id",
							"message_id",
							"idx",
							"src_addr",
							"dst_addr",
							"container_name",
							"container_image",
							"content",
							"created_at",
						}
						vals := []any{
							fmt.Sprintf("%v/%v", event.Tgid, event.Pid),
							fmt.Sprintf("%v", event.MessageId),
							fmt.Sprintf("%v", event.ChunkIdx),
							fmt.Sprintf("%v:%v", internal.IntToIp(event.Saddr), event.Sport),
							fmt.Sprintf("%v:%v", internal.IntToIp(event.Daddr), event.Dport),
							containerName,
							containerImage,
							internal.Readable(event.Buf[:], max(event.ChunkLen, 0)),
							"COMMIT_TIMESTAMP",
						}
						mut := internal.SpannerPayload{
							Table: "llm_prompt",
							Cols:  cols,
							Vals:  vals,
						}
						mutBufCh <- mut
					}

				case TYPE_REPORT_WRITE_SOCKET_INFO:
					fmt.Fprintf(&line, "[TYPE_REPORT_WRITE_SOCKET_INFO] key=%v, ", key)
					fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Saddr), event.Sport)
					fmt.Fprintf(&line, "dst=%v:%v", internal.IntToIp(event.Daddr), event.Dport)
					internalglog.LogInfo(line.String())

				case TYPE_UPROBE_SSL_READ:

				case TYPE_URETPROBE_SSL_READ:
					if event.ChunkIdx == CHUNK_END_IDX {
						continue
					}

					if eventState[key].http2.Load() == 1 && event.ChunkIdx == 0 && event.ChunkLen >= 9 {
						buf := bytes.NewReader(event.Buf[:])
						header := make([]byte, 9)
						_, err = buf.Read(header)
						if err != nil {
							glog.Errorf("[uretprobe/SSL_read] incomplete frame header: %v", err)
							continue
						}

						// Parse header: length is 24 bits (3 bytes), big-endian.
						length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
						frameType := header[3]
						flags := header[4]
						streamId := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF // mask out the reserved bit

						switch frameType {
						case FrameData:
						case FrameHeaders:
						default:
							if frameType >= FramePriority && frameType <= FrameContinuation {
								continue
							}
						}

						if frameType <= FrameContinuation {
							var h strings.Builder
							fmt.Fprintf(&h, "[uretprobe/SSL_read{_ex}] HTTP/2 Frame: type=0x%x, ", frameType)
							fmt.Fprintf(&h, "length=%d, flags=0x%x, streamId=%d, ", length, flags, streamId)
							fmt.Fprintf(&h, "totalLen=%v", event.TotalLen)
							internalglog.LogInfo(h.String())
						}
					}

					fmt.Fprintf(&line, "-> [uretprobe/SSL_read{_ex}] idx=%v, ", event.ChunkIdx)
					fmt.Fprintf(&line, "buf=%s, ", internal.Readable(event.Buf[:], max(event.ChunkLen, 0)))
					fmt.Fprintf(&line, "key=%v, totalLen=%v, chunkLen=%v, ", key, event.TotalLen, event.ChunkLen)
					fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Daddr), event.Dport)
					fmt.Fprintf(&line, "dst=%v:%v", internal.IntToIp(event.Saddr), event.Sport)
					func() {
						if !isk8s {
							return
						}
						ipToDomainMtx.Lock()
						defer ipToDomainMtx.Unlock()
						info, ok := ipToDomain[internal.IntToIp(event.Daddr).String()]
						if ok {
							fmt.Fprintf(&line, "srcDomain=%v ", info)
						}
					}()

					func() {
						if !isk8s {
							return
						}
						ipToContainerMtx.Lock()
						defer ipToContainerMtx.Unlock()
						info, ok := ipToContainer[internal.IntToIp(event.Saddr).String()]
						if ok {
							fmt.Fprintf(&line, "targetContainerName=%v ", info.Name)
						}
					}()
					internalglog.LogInfo(line.String())

					// Skip chunked end marker
					if event.TotalLen == 5 && event.ChunkLen == 5 {
						content := string(event.Buf[:event.ChunkLen])
						if content == "0\r\n\r\n" {
							break
						}
					}

					// use connection-based key (without message_id) to group all chunks for this response
					respKey := fmt.Sprintf("%v/%v/%v/%v/%v/%v", event.Tgid, event.Pid, event.Saddr, event.Daddr, event.Sport, event.Dport)
					bucketAny, _ := responseMap.LoadOrStore(respKey, &responseBucket{
						total:      int(event.TotalLen),
						lastUpdate: time.Now(),
					})
					bucket := bucketAny.(*responseBucket)
					
					// Update last activity time
					bucket.lastUpdate = time.Now()
					
					// Add chunk with its index for ordering
					bucket.chunks = append(bucket.chunks, event.Buf[:event.ChunkLen])
					bucket.chunkOrder = append(bucket.chunkOrder, int(event.Idx))
					bucket.received += int(event.ChunkLen)

					// Check if we should process (either complete or timeout)
					shouldProcess := false
					if bucket.received >= bucket.total {
						shouldProcess = true
						internalglog.LogInfof("llm_response: complete response received (%d/%d bytes)", bucket.received, bucket.total)
					} else if time.Since(bucket.lastUpdate) > 5*time.Second {
						shouldProcess = true
						internalglog.LogInfof("llm_response: timeout reached, processing partial response (%d/%d bytes)", bucket.received, bucket.total)
					} else {
						internalglog.LogInfof("llm_response: waiting for more chunks (%d/%d bytes)", bucket.received, bucket.total)
						break
					}

					if !shouldProcess {
						break
					}

					// Debug: log each chunk's index and size
					for idx, chunk := range bucket.chunks {
						order := -1
						if idx < len(bucket.chunkOrder) {
							order = bucket.chunkOrder[idx]
						}
						internalglog.LogInfof("llm_response: chunk %d (order=%d) size=%d", idx, order, len(chunk))
					}
					
					// Combine all chunks
					full := bytes.Join(bucket.chunks, nil)
					internalglog.LogInfof("llm_response: combined full response size=%d", len(full))

					// Separate headers and body
					i := bytes.Index(full, []byte("\r\n\r\n"))
					var headers string
					var body []byte
					var rawBody []byte
					if i > 0 {
						headers = string(full[:i])
						rawBody = full[i+4:]
						if strings.Contains(headers, "Transfer-Encoding: chunked") {
							internalglog.LogInfof("llm_response: decoding chunked body, rawBody size=%d", len(rawBody))
							decoded, err := decodeChunkedBody(rawBody)
							if err == nil {
								body = decoded
								internalglog.LogInfof("llm_response: chunked decoding successful, decoded size=%d", len(body))
							} else {
								internalglog.LogInfof("llm_response: chunked decoding failed: %v", err)
								body = rawBody // fallback
							}
						} else {
							body = rawBody
						}
					} else {
						body = full
					}

					// Check for gzip encoding
					if strings.Contains(headers, "Content-Encoding: gzip") {
						internalglog.LogInfof("llm_response: gzip detected, body size before decompression=%d", len(body))
						reader, err := gzip.NewReader(bytes.NewReader(body))
						if err == nil {
							decompressed, err := io.ReadAll(reader)
							reader.Close()
							if err == nil {
								body = decompressed
								internalglog.LogInfof("llm_response: gzip decompression successful, decompressed size=%d", len(body))
							} else {
								internalglog.LogInfof("llm_response: gzip read failed: %v", err)
							}
						} else {
							internalglog.LogInfof("llm_response: gzip reader creation failed: %v", err)
						}
					}
					internalglog.LogInfof("llm_response: headers=%q", headers)
					internalglog.LogInfof("llm_response: body=%q", body)

					// Validate content before saving - ensure it's valid UTF-8 text
					contentToSave := string(body)
					if !utf8.Valid(body) {
						internalglog.LogInfof("llm_response: invalid UTF-8 content, storing as base64")
						contentToSave = base64.StdEncoding.EncodeToString(body)
					} else if len(body) == 0 {
						internalglog.LogInfof("llm_response: empty body, skipping save")
						continue
					}

					// Save to Spanner (llm_response)
					if params.RunfSaveDb {
						var containerName, containerImage string
						func() {
							if !isk8s {
								return
							}
							ipToContainerMtx.Lock()
							defer ipToContainerMtx.Unlock()
							info, ok := ipToContainer[internal.IntToIp(event.Saddr).String()]
							if ok {
								containerName = info.Name
								containerImage = info.Image
							}
						}()

						cols := []string{
							"id",
							"message_id",
							"org_id",
							"idx",
							"comm",
							"src_addr",
							"dst_addr",
							"container_name",
							"container_image",
							"content",
							"created_at",
						}
						vals := []any{
							fmt.Sprintf("%v/%v", event.Tgid, event.Pid),
							fmt.Sprintf("%v", event.MessageId),
							"",  // org_id
							"0", // idx
							fmt.Sprintf("%s", event.Comm),
							fmt.Sprintf("%v:%v", internal.IntToIp(event.Saddr), event.Sport),
							fmt.Sprintf("%v:%v", internal.IntToIp(event.Daddr), event.Dport),
							containerName,
							containerImage,
							contentToSave,
							"COMMIT_TIMESTAMP",
						}
						mut := internal.SpannerPayload{
							Table: "llm_response",
							Cols:  cols,
							Vals:  vals,
						}
						mutBufCh <- mut
					}

					responseMap.Delete(respKey)
					break

				case TYPE_REPORT_READ_SOCKET_INFO:
					fmt.Fprintf(&line, "[TYPE_REPORT_READ_SOCKET_INFO] key=%v, ", key)
					fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Daddr), event.Dport)
					fmt.Fprintf(&line, "dst=%v:%v", internal.IntToIp(event.Saddr), event.Sport)
					internalglog.LogInfo(line.String())

				case TYPE_ANY:
					fmt.Fprintf(&line, "[TYPE_ANY] key=%v, totalLen=%v, ", key, event.TotalLen)
					fmt.Fprintf(&line, "src=%v:%v, ", internal.IntToIp(event.Saddr), event.Sport)
					fmt.Fprintf(&line, "dst=%v:%v", internal.IntToIp(event.Daddr), event.Dport)
					internalglog.LogInfo(line.String())

				default:
				}
			}
		}(i)
	}

	var count uint64
	var dropped uint64
	var record ringbuf.Record
	var event bpf.BpfEvent

	for {
		err = rd.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				internalglog.LogInfo("received signal, exiting...")
				close(eventSink)
				close(mutBufCh)
				break
			}

			glog.Errorf("reading from reader failed: %v", err)
			continue
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			glog.Errorf("parsing ringbuf event failed: %v", err)
			continue
		}
		// Increment and assign the global message_id
		event.MessageId = atomic.AddUint64(&globalMessageID, 1)

		count++
		if count%1000 == 0 {
			internalglog.LogInfof("%d events processed, %d events dropped", count, dropped)
		}

		key := fmt.Sprintf("%v/%v", event.Tgid, event.Pid)
		if _, ok := eventState[key]; !ok {
			eventState[key] = &eventStateT{}
		}

		select {
		case eventSink <- event:
		default:
			dropped++
		}
	}

	internalglog.LogInfof("%d events processed, %d events dropped", true, count, dropped)

	wg.Wait()
}

func setupUprobes(ex *link.Executable, links *[]link.Link, objs *bpf.BpfObjects) {
	l, err := ex.Uprobe("SSL_write", objs.UprobeSslWrite, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_write failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_write", objs.UretprobeSslWrite, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_write failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uprobe("SSL_write_ex", objs.UprobeSslWriteEx, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_write_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_write_ex", objs.UretprobeSslWriteEx, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_write_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uprobe("SSL_read", objs.UprobeSslRead, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_read failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_read", objs.UretprobeSslRead, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_read failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uprobe("SSL_read_ex", objs.UprobeSslReadEx, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_read_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_read_ex", objs.UretprobeSslReadEx, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_read_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}
}

func decodeChunkedBody(chunked []byte) ([]byte, error) {
	var body bytes.Buffer
	r := bytes.NewReader(chunked)

	for {
		// Read chunk size line until \r\n
		var sizeLine []byte
		for {
			b, err := r.ReadByte()
			if err == io.EOF {
				// End of data - this is normal for final chunk
				if body.Len() > 0 {
					return body.Bytes(), nil
				}
				return nil, fmt.Errorf("unexpected EOF while reading chunk size")
			}
			if err != nil {
				return nil, fmt.Errorf("error reading chunk size: %v", err)
			}
			if b == '\r' {
				// Look for \n after \r
				next, err := r.ReadByte()
				if err == nil && next == '\n' {
					break
				}
				// Put back the byte if it wasn't \n
				if err == nil {
					pos, _ := r.Seek(0, io.SeekCurrent)
					r.Seek(pos-1, io.SeekStart)
				}
				sizeLine = append(sizeLine, b)
			} else {
				sizeLine = append(sizeLine, b)
			}
		}

		sizeStr := strings.TrimSpace(string(sizeLine))
		if sizeStr == "" {
			continue
		}

		// Handle potential extensions after semicolon (chunk-extensions)
		if idx := strings.Index(sizeStr, ";"); idx >= 0 {
			sizeStr = sizeStr[:idx]
		}

		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size '%s': %v", sizeStr, err)
		}

		if size == 0 {
			// End of chunks - consume any trailing headers and final \r\n
			for {
				line, err := r.ReadByte()
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
				if line == '\r' {
					next, err := r.ReadByte()
					if err == nil && next == '\n' {
						// Found final \r\n, we're done
						break
					}
				}
			}
			break
		}

		// Read chunk data
		chunk := make([]byte, size)
		n, err := io.ReadFull(r, chunk)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Partial read at end - this can happen with incomplete data
			if n > 0 {
				body.Write(chunk[:n])
			}
			return body.Bytes(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading chunk data (expected %d bytes): %v", size, err)
		}

		body.Write(chunk)

		// Read trailing \r\n after chunk data - be more tolerant
		trailer1, err1 := r.ReadByte()
		trailer2, err2 := r.ReadByte()
		if err1 == io.EOF || err2 == io.EOF {
			// End of data after chunk - might be incomplete
			return body.Bytes(), nil
		}
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("reading chunk trailer: %v, %v", err1, err2)
		}
		if trailer1 != '\r' || trailer2 != '\n' {
			return nil, fmt.Errorf("expected \\r\\n after chunk, got %02x%02x", trailer1, trailer2)
		}
	}

	return body.Bytes(), nil
}
