'''
    demo工具
'''
from pwn import *

from base_data import *                 # 基础数据

from heap import *                      # 堆工具
from fmtarg import *                    # 格式化字符串漏洞利用工具
from IO_attack import *                 # _IO_FILE结构体漏洞利用工具

from HOB import *                       # House of Banana漏洞利用工具

from kernel_template import *           # 内核漏洞利用工具(模板)
from kernel import *                    # 内核漏洞利用工具

from proto_c_reverse import *           # proto_c逆向工具

