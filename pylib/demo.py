'''
    demo工具
'''
from pwn import *
import os
import shutil

from base_data import *                 # 基础数据

from heap import *                      # 堆工具
from fmtarg import *                    # 格式化字符串漏洞利用工具
from IO_attack import *                 # _IO_FILE结构体漏洞利用工具

from HOB import *                       # House of Banana漏洞利用工具
from HOP import *                       # House of Pig漏洞利用工具

from kernel_template import *           # 内核漏洞利用工具(模板)
from kernel import *                    # 内核漏洞利用工具

from proto_c_reverse import *                   # proto_c逆向工具

def libc_download(libc_path):
    """
        根据libc文件下载对应的libc并嵌入调试信息
        
        参数:
            libc_path: libc文件路径
        
        示例:
            libc_download('./libc.so.6')
    """
    # 下载libc库
    libc_dir = libcdb.download_libraries(libc_path)
    target_dir = os.getcwd()+'/libc_dir'
    if len(os.listdir(libc_dir)) >= 1:
        log.info('libc下载目录 : ' + libc_dir)
        log.info('libc拷贝目录 : ' + target_dir)
    else:
        log.error('libc库下载失败')
        return None
    
    # 确保目标目录存在
    os.makedirs(target_dir, exist_ok=True)
    
    # 遍历源目录中的所有文件
    for file_name in os.listdir(libc_dir):
        source_file = os.path.join(libc_dir, file_name)
        target_file = os.path.join(target_dir, file_name)
        # 检查是否是文件（忽略子目录）
        if os.path.isfile(source_file):
          shutil.copy(source_file, target_file)  # 拷贝文件

    # 输出
    os.system(f'echo -n "源libc sha256 : ";sha256sum {libc_path} | grep -o \'^[^ ]*\'')
    os.system(f'echo -n "源libc string : ";strings {libc_path} | grep \'GNU C Library\'')
    print('')
    os.system(f'echo -n "匹配libc sha256 : ";find {target_dir} -type f -name "libc.so.6" -o -regex ".*/libc-[0-9]+\\.[0-9]+\\.so" | xargs sha256sum | grep -o \'^[^ ]*\'')
    os.system(f'echo -n "匹配libc string : ";find {target_dir} -type f -name "libc.so.6" -o -regex ".*/libc-[0-9]+\\.[0-9]+\\.so" | xargs strings | grep \'GNU C Library\'')
    
    return libc_dir

