#!/bin/bash
echo "打包文件系统"
(cd rootfs && find .  | cpio -o --format=newc > ../rootfs.cpio)
(cd driver && find *.ko  | cpio -o --format=newc -A -F ../rootfs.cpio)
echo "打包完成"
