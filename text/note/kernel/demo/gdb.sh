#!/bin/bash
gdb ./vmlinux -q \
    -ex "target remote localhost:1234" \
    -ex "add-symbol-file ./driver/driver.ko 0xffffffffc0002000" \
    -ex "b my_read" \
    -ex "b *my_read" \
    -ex "c"
    
    # -ex "b my_read" \
    
    # -ex "b *0xFFFFFFFF81E00010" \ 进入
    # -ex "b *0xFFFFFFFF81E00A34" \ 退出
