```sh
# vmlinux.h:
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Only needed when C files are updated:
$ go generate

# Normal builds:
$ make
```
