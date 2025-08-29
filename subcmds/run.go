//go:build linux

package subcmds

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
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
	rawBody    []byte //continuous buffer for full HTTP response
	received   int
	total      int // can be filled from Content-Length if known
	lastUpdate time.Time
	mu         *sync.Mutex // thread safety
	processing bool
	processed  bool
}

var (
	buckets    = make(map[string]*responseBucket) // key = connKey
	bucketsMtx = &sync.Mutex{}
)

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

	// Start background cleanup for response buckets
	backgroundCleanup()

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
				// Delete buckets that are either stale (>60s) or processed (>10s ago)
				if now.Sub(bucket.lastUpdate) > 60*time.Second ||
					(bucket.processed && now.Sub(bucket.lastUpdate) > 10*time.Second) {
					internalglog.LogInfof("llm_response: cleaning up bucket for key %v (processed=%v, age=%v)",
						key, bucket.processed, now.Sub(bucket.lastUpdate))
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
					// start collecting response chunks
					connKey := fmt.Sprintf("%s:%d-%s:%d-%d",
						internal.IntToIp(event.Saddr), event.Sport,
						internal.IntToIp(event.Daddr), event.Dport,
						event.Pid,
					)

					bucketsMtx.Lock()
					bucket, ok := buckets[connKey]
					if !ok {
						bucket = &responseBucket{mu: &sync.Mutex{}}
						buckets[connKey] = bucket
					}
					bucketsMtx.Unlock()

					// Append the new SSL payload only if valid
					bucket.mu.Lock()
					if event.ChunkLen > 0 && int(event.ChunkLen) <= len(event.Buf) && event.ChunkIdx != 0xFFFFFFFF {
						bucket.rawBody = append(bucket.rawBody, event.Buf[:event.ChunkLen]...)
						bucket.received += int(event.ChunkLen)
						bucket.lastUpdate = time.Now()
					} else if event.ChunkLen == 0 {
						// ChunkLen of 0 might indicate end of stream, update timestamp but don't append data
						bucket.lastUpdate = time.Now()
					}
					// Negative ChunkLen or CHUNKED_END_IDX: do not append, skip silently
					bucket.mu.Unlock()

					// Try to parse headers
					headerEnd := bytes.Index(bucket.rawBody, []byte("\r\n\r\n"))
					if headerEnd == -1 || headerEnd+4 > len(bucket.rawBody) {
						// Headers incomplete or body out of bounds → wait for more
						break
					}

					headers := string(bucket.rawBody[:headerEnd])
					body := bucket.rawBody[headerEnd+4:]

					// Only process if truly complete (Content-Length or chunked)
					if isResponseComplete(headers, body) && !bucket.processed && !bucket.processing {
						bucket.processing = true // mark immediately to avoid duplicate goroutines
						go func(connKey string, b *responseBucket) {
							processCompleteResponse(b)
							// Reset bucket for next response on same connection
							b.mu.Lock()
							b.rawBody = b.rawBody[:0]
							b.received = 0
							b.total = 0
							b.processing = false
							b.processed = false
							b.mu.Unlock()
						}(connKey, bucket)
					}

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

// checks whether HTTP response is complete
func isResponseComplete(headers string, body []byte) bool {
	// for Content-Length
	if clIdx := strings.Index(headers, "Content-Length:"); clIdx != -1 {
		var length int
		_, err := fmt.Sscanf(headers[clIdx:], "Content-Length: %d", &length)
		if err == nil && len(body) >= length {
			return true
		}
	}

	// for Chunked transfer encoding
	if strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked") {
		if isChunkedBodyComplete(body) {
			return true
		}
	}

	return false
}

// supports gzip/deflate
func decompressData(data []byte, method string) ([]byte, error) {
	switch strings.ToLower(method) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip reader creation failed: %v", err)
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		return io.ReadAll(reader)
	default:
		return data, nil
	}
}

// extracts AI response text from JSON
func parseAIResponse(jsonBody []byte) string {
	// Try Gemini schema
	var gemini struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(jsonBody, &gemini); err == nil {
		if len(gemini.Candidates) > 0 && len(gemini.Candidates[0].Content.Parts) > 0 {
			return gemini.Candidates[0].Content.Parts[0].Text
		}
	}

	// Try OpenAI schema
	var openai struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(jsonBody, &openai); err == nil {
		if len(openai.Choices) > 0 {
			return openai.Choices[0].Message.Content
		}
	}

	// Fallback
	return string(jsonBody)
}

func processCompleteResponse(bucket *responseBucket) {
	if bucket.processed {
		return
	}
	bucket.processed = true

	data := bucket.rawBody

	// Split headers/body
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		fmt.Println(" Incomplete headers")
		return
	}
	headers := string(data[:headerEnd])
	body := data[headerEnd+4:]

	// decode chunks first
	if strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked") {
		if fullBody, ok := parseChunkedBody(body); ok {
			body = fullBody
		} else {
			fmt.Println("Failed to parse chunked body")
			return
		}
	}

	// compressed body (gzip/deflate)
	if strings.Contains(strings.ToLower(headers), "content-encoding: gzip") {
		if decompressed, err := decompressData(body, "gzip"); err == nil {
			body = decompressed
		} else {
			fmt.Println("Gzip decompression failed:", err)
		}
	} else if strings.Contains(strings.ToLower(headers), "content-encoding: deflate") {
		if decompressed, err := decompressData(body, "deflate"); err == nil {
			body = decompressed
		} else {
			fmt.Println(" Deflate decompression failed:", err)
		}
	}

	// Parse JSON and extract AI text
	fmt.Println("Raw JSON body:", string(body))
	aiText := parseAIResponse(body)
	fmt.Println("Final AI Response:")
	fmt.Println(aiText)
}

func isChunkedBodyComplete(body []byte) bool {
	return bytes.Contains(body, []byte("0\r\n\r\n"))
}

// backgroundCleanup launches a goroutine that removes stale buckets
func backgroundCleanup() {
	go func() {
		for {
			time.Sleep(30 * time.Second)

			bucketsMtx.Lock()
			for connKey, bucket := range buckets {
				bucket.mu.Lock()
				idle := time.Since(bucket.lastUpdate)
				processed := bucket.processed

				// Only process if chunked body is complete
				headerEnd := bytes.Index(bucket.rawBody, []byte("\r\n\r\n"))
				var headers string
				var body []byte
				if headerEnd != -1 && headerEnd+4 <= len(bucket.rawBody) {
					headers = string(bucket.rawBody[:headerEnd])
					body = bucket.rawBody[headerEnd+4:]
				}

				shouldProcess := false
				if idle > 60*time.Second && !processed && len(bucket.rawBody) > 0 {
					if strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked") {
						if isChunkedBodyComplete(body) {
							shouldProcess = true
						}
					} else {
						shouldProcess = true
					}
				}

				if shouldProcess {
					fmt.Printf("[cleanup] Forcing process of possibly-incomplete response for %s (idle=%v)\n", connKey, idle)
					bucket.processing = true
					processCompleteResponse(bucket)
					bucket.processed = true
				}
				bucket.mu.Unlock()
				if idle > 120*time.Second || (bucket.processed && idle > 10*time.Second) {
					fmt.Printf("Cleaning up stale bucket for %s (processed=%v, idle=%v)\n", connKey, bucket.processed, idle)
					delete(buckets, connKey)
				}
			}
			bucketsMtx.Unlock()
		}
	}()
}

// parses an HTTP/1.1 chunked transfer body into a full byte slice.
func parseChunkedBody(body []byte) ([]byte, bool) {
	reader := bytes.NewReader(body)
	var result bytes.Buffer

	for {
		// Read until CRLF for chunk size
		line, err := readLine(reader)
		if err != nil {
			return nil, false // incomplete
		}

		// Parse size in hex
		size, err := strconv.ParseInt(strings.TrimSpace(string(line)), 16, 64)
		if err != nil {
			return nil, false // invalid
		}

		if size == 0 {
			// Must be followed by final CRLF
			trailer, _ := readLine(reader)
			if string(trailer) == "" {
				return result.Bytes(), true
			}
			return result.Bytes(), true // ignoring trailers for now
		}

		// Read exactly <size> bytes
		chunk := make([]byte, size)
		n, err := reader.Read(chunk)
		if err != nil || n < int(size) {
			return nil, false // incomplete
		}
		result.Write(chunk)

		// Expect CRLF after data
		crlf := make([]byte, 2)
		if _, err := reader.Read(crlf); err != nil || string(crlf) != "\r\n" {
			return nil, false // malformed
		}
	}
}

// readLine reads until CRLF, returns the line (without CRLF).
func readLine(r *bytes.Reader) ([]byte, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\r' {
			// Expect \n next
			next, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			if next == '\n' {
				return line, nil
			}
			return nil, fmt.Errorf("expected LF after CR")
		}
		line = append(line, b)
	}
}
