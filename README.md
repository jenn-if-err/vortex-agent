[![main](https://github.com/flowerinthenight/vortex-agent/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/vortex-agent/actions/workflows/main.yml)

> [!CAUTION]
> Alpha-level software. Use with caution.

Setup notes:

```sh
# If first clone:
$ git clone --recurse-submodules https://github.com/flowerinthenight/vortex-agent

# Note only; we use the vmlinux.h submodule instead of the generated header.
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Only needed when C file(s) are updated:
$ go generate

# Normal builds:
$ make

# Run:
$ [sudo] ./bin/vortex-agent run --logtostderr

# To be able to list pods:
$ kubectl create clusterrolebinding default-view \
  --clusterrole=view \
  --serviceaccount=default:default

# Deploy to k8s as daemonset:
$ kubectl create -f daemonset.yaml
```

> [!WARNING]
> Work-in-progress: build won't allow to load `vortex-agent` yet.

```sh
# Clone stable Linux kernel:
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
```
