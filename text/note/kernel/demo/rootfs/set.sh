#!/bin/bash
mkdir -pv {bin,sbin,etc,proc,sys,dev,home/ctf,root,tmp,lib64,lib/x86_64-linux-gnu,usr/{bin,sbin}}
touch etc/inittab
mkdir etc/init.d
touch etc/init.d/rcS
chmod +x ./etc/init.d/rcS

echo '::sysinit:/etc/init.d/rcS' > etc/inittab
echo '::askfirst:/bin/ash' >> etc/inittab
echo '::ctrlaltdel:/sbin/reboot' >> etc/inittab
echo '::shutdown:/sbin/swapoff -a' >> etc/inittab
echo '::shutdown:/bin/umount -a -r' >> etc/inittab
echo '::restart:/sbin/init' >> etc/inittab

# 初始用户
echo "root:x:0:0:root:/root:/bin/sh" > etc/passwd
echo "ctf:x:1000:1000:ctf:/home/ctf:/bin/sh" >> etc/passwd
echo "root:x:0:" > etc/group
echo "ctf:x:1000:" >> etc/group
echo "none /dev/pts devpts gid=5,mode=620 0 0" > etc/fstab