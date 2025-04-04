'''
    demo工具
'''
from pwn import *
import telnetlib
import os
import shutil 

from base_data import *

from heap import *                      # 堆漏洞利用工具
from fmtarg import *                    # 格式化字符串漏洞利用工具
from HOB import *                       # House of Banana漏洞利用工具
from HOP import *                       # House of Pig漏洞利用工具
from IO_attack import *                 # _IO_FILE结构体漏洞利用工具

from kernel_template import *           # 内核漏洞利用工具
from kernel import *                    # 内核漏洞利用工具


def telnet(r):
    tn = telnetlib.Telnet()
    tn.sock = r.sock
    tn.interact()


def libc_download(libc_name, all_file=False):
    '''
        下载libc库
    '''
    libc_dir = libcdb.download_libraries(libc_name)
    target_dir = os.getcwd()+'/libc_dir'
    print('libc下载目录 : ' + libc_dir)
    
    # 确保目标目录存在
    os.makedirs(target_dir, exist_ok=True)
    
    
    # 遍历源目录中的所有文件
    for file_name in os.listdir(libc_dir):
        source_file = os.path.join(libc_dir, file_name)
        target_file = os.path.join(target_dir, file_name)
        # 检查是否是文件（忽略子目录）
        if os.path.isfile(source_file):
          shutil.copy(source_file, target_file)  # 拷贝文件
    return libc_dir