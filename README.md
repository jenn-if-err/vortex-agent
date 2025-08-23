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

If possible, test using cloud VMs, or k8s, but for specific kernel versions, below is a rough guide on how to setup a custom kernel with a Debian system using [QEMU](https://www.qemu.org/).

> [!NOTE]
> Still incomplete; build can't load `vortex-agent` yet. If you can make it work, update this guide.

```sh
# Install prerequisites:
$ sudo apt update
$ sudo apt install make gcc flex bison libncurses-dev libelf-dev libssl-dev debootstrap dwarves

# Clone stable Linux kernel:
$ cd $WORKDIR/
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git

# Checkout desired version (tag):
$ cd linux-stable/
$ git checkout -b v6.6.102 v6.6.102

# Configure kernel build:
$ $VORTEX_ROOT/tools/config-kernel.sh
$ make -j$(nproc)

# Create a Debian Bullseye Linux image:
$ cd ../
$ mdkir -p debian-bullseye/
$ cd debian-bullseye/
$ wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
$ chmod +x create-image.sh
$ ./create-image.sh --feature full

# Run the image:
$ cd ../
$ qemu-system-x86_64 \
      -m 2G \
      -smp 2 \
      -kernel linux-stable/arch/x86/boot/bzImage \
      -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
      -drive file=debian-bullseye/bullseye.img,format=raw \
      -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
      -net nic,model=e1000 \
      -enable-kvm \
      -nographic \
      -pidfile vm.pid \
      2>&1 | tee vm.log

# On another terminal, you can use scp and ssh:
$ scp -i debian-bullseye/bullseye.id_rsa -P 10021 \
      -o "StrictHostKeyChecking no" \
      vortex-agent/bin/vortex-agent \
      root@localhost:~/

$ ssh -i debian-bullseye/bullseye.id_rsa -p 10021 \
      -o "StrictHostKeyChecking no" root@localhost

# Close the VM (from ssh terminal):
$ poweroff
```
