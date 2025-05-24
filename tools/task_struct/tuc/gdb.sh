#!/bin/bash
gdb ./vmlinux -q \
    -ex "target remote localhost:1234" \
    -ex "add-symbol-file ./tuc/tuc.ko 0xffffffffc0000000" \
    -ex "b *0xffffffffc00000cc" \
    -ex "c"
