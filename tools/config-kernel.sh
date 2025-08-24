#!/bin/bash

make defconfig
make kvm_guest.config

# Required for Debian Stretch and later:
./scripts/config --set-val CONFIG_CONFIGFS_FS y
./scripts/config --set-val CONFIG_SECURITYFS y

# BPF-related configs:
./scripts/config --set-val CONFIG_BPF y
./scripts/config --set-val CONFIG_BPF_SYSCALL y
./scripts/config --set-val CONFIG_MODULES y
./scripts/config --set-val CONFIG_BPF_EVENTS y
./scripts/config --set-val CONFIG_PERF_EVENTS y
./scripts/config --set-val CONFIG_HAVE_PERF_EVENTS y
./scripts/config --set-val CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT y
./scripts/config --set-val CONFIG_DEBUG_INFO y
./scripts/config --set-val CONFIG_DEBUG_INFO_BTF y
./scripts/config --set-val CONFIG_NET_CLS_BPF y
./scripts/config --set-val CONFIG_NET_SCH_INGRESS y
./scripts/config --set-val CONFIG_BPF_JIT y
./scripts/config --set-val CONFIG_HAVE_BPF_JIT y
./scripts/config --set-val CONFIG_CGROUP_BPF y
./scripts/config --set-val CONFIG_KPROBES y
./scripts/config --set-val CONFIG_KPROBE_EVENTS y
./scripts/config --set-val CONFIG_KPROBES_ON_FTRACE y
./scripts/config --set-val CONFIG_UPROBES y
./scripts/config --set-val CONFIG_UPROBE_EVENTS y
./scripts/config --set-val CONFIG_TRACEPOINTS y
./scripts/config --set-val CONFIG_HAVE_SYSCALL_TRACEPOINTS y
./scripts/config --set-val CONFIG_FTRACE y
./scripts/config --set-val CONFIG_FTRACE_SYSCALLS y

./scripts/config --set-val CONFIG_CMDLINE_BOOL y
echo 'CONFIG_CMDLINE="net.ifnames=0"' >> .config

make olddefconfig
