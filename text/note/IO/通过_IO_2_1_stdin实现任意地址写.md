# 通过_IO_2_1_stdin实现任意地址写数据

## libc-2.39下, null字节写入实现任意地址写

1. 修改_IO_2_1_stdin->_IO_buf_base的最低位为null, 即可设置_IO_2_1_stdin->_IO_buf_base = &_IO_2_1_stdin->_IO_write_base
2. 写入p64(0) * 3 + p64(目标地址start) + p64(目标地址end)
3. 再次写入数据即可写入目标地址

这个方法可以结合QWB_2025_bph