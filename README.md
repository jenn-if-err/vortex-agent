```sh
# If first clone:
$ git clone --recurse-submodules https://github.com/flowerinthenight/vortex-agent

# Note only; here, we use the vmlinux.h submodule:
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Only needed when C files are updated:
$ go generate

# Normal builds:
$ make
```
