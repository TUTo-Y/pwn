#!/bin/bash
qemu-system-x86_64 \
    -m 256M \
    -nographic \
    -kernel ./bzImage \
    -initrd  ./rootfs.cpio \
    -append "root=/dev/ram rw rdinit=/sbin/init console=ttyS0 oops=panic panic=1 loglevel=3 quiet nokaslr" \
    -smp cores=2,threads=1 \
    -cpu kvm64 \
    -s \
    -serial mon:stdio \
    -serial pty