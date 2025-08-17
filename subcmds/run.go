//go:build linux

package subcmds

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/signal"
	"path/filepath"
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
	"golang.org/x/sys/unix"
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

func RunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run as agent (long running)",
		Long:  `Run as agent (long running).`,
		Run: func(cmd *cobra.Command, args []string) {
			internalglog.LogInfof("Running vortex-agent as service (%v)", time.Now().Format(time.RFC3339))
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
	cmd.Flags().StringVar(&params.RunfComm, "comm", "", "Process name to trace, max 16 bytes, default all")
	cmd.Flags().StringVar(&params.RunfUprobes, "uprobes", "", "Lib/bin files to attach to uprobes (comma-separated)")
	cmd.Flags().BoolVar(&params.RunfSaveDb, "savedb", false, "If set to true, save data to Spanner")
	cmd.Flags().BoolVar(&params.RunfDisableLogs, "nologs", false, "If set to true, disable logs (for performance)")
	return cmd
}

func run(ctx context.Context, done chan error) {
	defer func() { done <- nil }()

	sslTestOnly := false

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

	if params.RunfComm != "" {
		var comm [16]byte
		copy(comm[:], params.RunfComm)
		err := objs.TraceComm.Put(uint32(0), comm)
		if err != nil {
			glog.Errorf("objs.TraceCommSock.Put failed: %v", err)
		} else {
			internalglog.LogInfof("tracing only for [%s]", params.RunfComm)
		}
	}

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

	// NOTE: TEST ONLY: TO BE REMOVED LATER (start).
	cgroupPath, err := findCgroupPath()
	if err != nil {
		glog.Errorf("findCgroupPath failed: %v", err)
	} else {
		// sockMapPath := "/sys/fs/bpf/sk_msg_sock_map"

		// Pinning the map is necessary for the sk_msg program to find it.
		// We must remove any previous pin first.
		// os.Remove(sockMapPath)
		// if err := os.MkdirAll(filepath.Dir(sockMapPath), 0755); err != nil {
		// 	glog.Errorf("MkdirAll (%v) failed: %v", sockMapPath, err)
		// } else {
		// 	// Pin the sock_hash map to the BPF filesystem. This is how the
		// 	// sock_ops and sk_msg programs will share the map.
		// 	if err := objs.SockMap.Pin(sockMapPath); err != nil {
		// 		glog.Errorf("pinning %v failed: %v", sockMapPath, err)
		// 	} else {
		// 		glog.Infof("%v pinned", sockMapPath)
		// 		defer func() {
		// 			objs.SockMap.Unpin()
		// 			os.Remove(sockMapPath)
		// 		}()
		// 	}
		// }

		// The sock_ops program is attached to the cgroup.
		// l, err = link.AttachCgroup(link.CgroupOptions{
		// 	Path:    cgroupPath,
		// 	Attach:  ebpf.AttachCGroupSockOps,
		// 	Program: objs.BpfSockopsHandler,
		// })

		// if err != nil {
		// 	glog.Errorf("attaching sock_ops to %v failed: %v", cgroupPath, err)
		// } else {
		// 	hostLinks = append(hostLinks, l)
		// 	glog.Infof("sock_ops attached to %s", cgroupPath)
		// }

		// The sk_msg program must be attached to the sock_hash map using a raw link.
		// This is the general-purpose attachment function for link types that don't
		// have a dedicated helper.
		// err = link.RawAttachProgram(link.RawAttachProgramOptions{
		// 	Program: objs.BpfSkMsgHandler,
		// 	Target:  objs.SockMap.FD(),
		// 	Attach:  ebpf.AttachSkMsgVerdict,
		// })

		// if err != nil {
		// 	glog.Errorf("RawAttachProgram failed: %v", err)
		// } else {
		// 	glog.Infof("sk_msg program attached to sock_map")
		// 	defer func() {
		// 		link.RawDetachProgram(link.RawDetachProgramOptions{
		// 			Program: objs.BpfSkMsgHandler,
		// 			Target:  objs.SockMap.FD(),
		// 			Attach:  ebpf.AttachSkMsgVerdict,
		// 		})
		// 	}()
		// }

		_ = cgroupPath
	}
	// NOTE: TEST ONLY: TO BE REMOVED LATER (end).

	isk8s := internal.IsK8s()
	uprobeFiles := strings.Split(params.RunfUprobes, ",")

	if !isk8s {
		libsslPath, err := internal.FindLibSSL("")
		if err != nil {
			glog.Errorf("Error finding libssl.so: %v", err)
			return
		}

		uprobeFiles = append(uprobeFiles, libsslPath)
		for _, uf := range uprobeFiles {
			if uf == "" {
				continue // skip empty entries
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
	}

	ipToDomain := make(map[string]string) // key=ip, value=domain
	var ipToDomainMtx sync.Mutex
	ipToDomainCtx := internal.ChildCtx(ctx)

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

				// ---------------------------------------------
				// TODO: fn is adding to list outside of goroutine!
				func() {
					var libs []string
					rootPath := fmt.Sprintf("/proc/%d/root", pid)
					libsslPath, _ := internal.FindLibSSL(rootPath)
					if libsslPath != "" {
						libs = append(libs, libsslPath)
					}

					nodeBinPath, _ := internal.FindNodeBin(rootPath)
					if nodeBinPath != "" {
						libs = append(libs, nodeBinPath)
					}

					if len(libs) == 0 {
						return
					}

					for _, lib := range libs {
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
				// ---------------------------------------------

				cgroupb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
				if err != nil {
					glog.Errorf("ReadFile failed: %v", err)
					return
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

	mutBuf := make([]internal.SpannerPayload, 0, 1000)
	mutBufCh := make(chan internal.SpannerPayload, 2048)

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
				if len(mutBuf) >= 1000 {
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

					if !isk8s && !sslTestOnly {
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
					if !isk8s && !sslTestOnly {
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
					if event.ChunkIdx == CHUNK_END_IDX {
						continue
					}

					if strings.HasPrefix(internal.Readable(event.Buf[:15], 15), "PRI * HTTP/2.0") {
						eventState[key].http2.Store(1)
					}

					if eventState[key].http2.Load() == 1 && event.ChunkIdx == 0 && event.ChunkLen >= 9 {
						buf := bytes.NewReader(event.Buf[:])
						header := make([]byte, 9)
						_, err = buf.Read(header)
						if err != nil {
							glog.Errorf("[uretprobe/SSL_write] incomplete frame header: %v", err)
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
							fmt.Fprintf(&h, "[uretprobe/SSL_write{_ex}] HTTP/2 Frame: type=0x%x, ", frameType)
							fmt.Fprintf(&h, "length=%d, flags=0x%x, streamId=%d, ", length, flags, streamId)
							fmt.Fprintf(&h, "totalLen=%v", event.TotalLen)
							internalglog.LogInfof(h.String())
						}
					}

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
							fmt.Fprintf(&line, "containerName=%v", info.Name)
						}
					}()
					internalglog.LogInfo(line.String())

					if strings.Contains(fmt.Sprintf("%s", event.Comm), "node") || (strings.Contains(fmt.Sprintf("%s", event.Buf[:]), "python")) && params.RunfSaveDb {
						cols := []string{
							"id",
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
							fmt.Sprintf("%v", event.ChunkIdx),
							fmt.Sprintf("%s", event.Comm),
							fmt.Sprintf("%v:%v", internal.IntToIp(event.Saddr), event.Sport),
							fmt.Sprintf("%v:%v", internal.IntToIp(event.Daddr), event.Dport),
							containerName,
							containerImage,
							internal.Readable(event.Buf[:], max(event.ChunkLen, 0)),
							"COMMIT_TIMESTAMP",
						}
						mut := internal.SpannerPayload{
							Table: "llm_prompts",
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
					internalglog.LogInfo(line.String())

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
	l, err := ex.Uprobe("SSL_write", objs.UprobeSSL_write, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_write failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_write", objs.UretprobeSSL_write, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_write failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uprobe("SSL_write_ex", objs.UprobeSSL_writeEx, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_write_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_write_ex", objs.UretprobeSSL_writeEx, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_write_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_read failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_read", objs.UretprobeSSL_read, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_read failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uprobe("SSL_read_ex", objs.UprobeSSL_readEx, nil)
	if err != nil {
		glog.Errorf("uprobe/SSL_read_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}

	l, err = ex.Uretprobe("SSL_read_ex", objs.UretprobeSSL_readEx, nil)
	if err != nil {
		glog.Errorf("uretprobe/SSL_read_ex failed: %v", err)
	} else {
		*links = append(*links, l)
	}
}

func findCgroupPath() (string, error) {
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
