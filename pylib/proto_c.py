from pwn import *
import os

PROTOBUF_C_LABEL = {0:'required', 1:'optional', 2:'repeated', 3:''}
PROTOBUF_C_TYPE  = {
                    0:'int32', 
                    1:'sint32', 
                    2:'sfixed32', 
                    3:'int64', 
                    4:'sint64', 
                    5:'sfixed64', 
                    6:'uint32', 
                    7:'fixed32', 
                    8:'uint64', 
                    9:'fixed64', 
                    10:'float', 
                    11:'double', 
                    12:'bool', 
                    13:'enum', 
                    14:'string', 
                    15:'bytes', 
                    16:'message'}

class enum:
    content_direct = {} # 确保每个enum只解析一次, {address: enum对象}
    content_list = []   # 列表存储所有解析的enum对象
    
    def __init__(self, elf, address):
        self.elf            = elf       # ELF对象
        self.address        = address   # 偏移地址
        
        self.package_name   = ''        # 所属包名称
        self.enum_name      = ''        # 枚举名称
        
        self.member_num     = 0         # 成员数量
        
        self.name           = []        # 名称
        self.value          = []        # ID
    
    def analy(self):
        '''
            解析enum的相关信息
        '''
        # 检查当前地址是否被解析
        if enum.content_direct.get(self.address) is not None:
            return enum.content_direct[self.address]
        enum.content_direct[self.address] = self
        enum.content_list.append(self)
        
        # 获取包名称和枚举名称
        pack_enum_name = str(self.elf.string(u64(self.elf.read(self.address + 0x8, 8))), 'utf-8')
        pack_name = str(self.elf.string(u64(self.elf.read(self.address + 0x20, 8))), 'utf-8')
        
        self.package_name = pack_name
        self.enum_name = pack_enum_name[len(pack_name)+1:] if pack_name else pack_enum_name
        
        # 获取成员数量
        self.member_num = u32(self.elf.read(self.address + 5 * 0x8, 4))
        
        # 获取成员地址
        member_addr = u64(self.elf.read(self.address + 6 * 0x8, 8))
        
        # 解析每个成员
        member = [self.elf.read(member_addr + i * 0x8 * 3, 0x8 * 3) for i in range(self.member_num)]
        for i in member:
            name = str(self.elf.string(u64(i[:0x8])), 'utf-8')
            value = u32(i[0x10:0x14])
            
            self.name.append(name)
            self.value.append(value)
        
        return self
        
    def print(self, space='', file=sys.stdout):
        
        print(f"{space}enum {self.enum_name}", file=file)
        print(f"{space}{{", file=file)
        for i in range(self.member_num):
            print(f"{space}\t{self.name[i]} = {self.value[i]};", file=file)
        print(f"{space}}}\n", file=file)
        pass
        
class message:
    content_direct = {} # 确保每个message只解析一次, {address: message对象}
    content_list = []   # 列表存储所有解析的message对象
    
    def __init__(self, elf, address):
        self.elf            = elf       # ELF对象
        self.address        = address   # 偏移地址
        
        self.package_name   = ''        # 包名称
        self.msg_name       = ''        # 消息名称
        
        self.member_num     = 0         # 成员数量
        
        self.modifier       = []        # 修饰符
        self.type           = []        # 类型
        self.name           = []        # 名称
        self.id             = []        # ID
        
        self.child_enum     = []        # 子枚举
        self.child_message  = []        # 子message
    
    def analy(self):
        '''
            解析message的相关信息
        '''
        # 检查当前地址是否被解析
        if message.content_direct.get(self.address) is not None:
            return message.content_direct[self.address]
        message.content_direct[self.address] = self
        message.content_list.append(self)
        
        # 获取包名称和消息名称
        pack_msg_name = str(self.elf.string(u64(self.elf.read(self.address + 0x8, 8))), 'utf-8')
        pack_name = str(self.elf.string(u64(self.elf.read(self.address + 0x20, 8))), 'utf-8')
        self.package_name = pack_name
        self.msg_name = pack_msg_name[len(pack_name)+1:] if pack_name else pack_msg_name
        
        # 获取成员数量
        self.member_num = u32(self.elf.read(self.address + 6 * 0x8, 4))
        
        # 获取成员地址
        member_addr = u64(self.elf.read(self.address + 7 * 0x8, 8))
        
        # 解析每个成员
        member = [self.elf.read(member_addr + i * 0x48, 0x48) for i in range(self.member_num)]
        for i in member:
            name = str(self.elf.string(u64(i[:8])), 'utf-8')
            id = u32(i[8:12])
            modifier = PROTOBUF_C_LABEL[u32(i[12:16])]
            type = PROTOBUF_C_TYPE[u32(i[16:20])]
            
            type_ptr = u64(i[0x20:0x28])
            # 检查是否有子message或者子enum
            if type == 'message':
                if type_ptr == 0:
                    log.warn(f"类型为message的成员 {self.package_name}.{self.msg_name}{{{modifier} {type} {name} = {id}}} 的类型指针为0，可能是未定义的类型。")
                else:
                    new = message(self.elf, type_ptr).analy()
                    type = new.package_name + '.' + new.msg_name 
            elif type == 'enum':
                if type_ptr == 0:
                    log.warn(f"类型为enum的成员 {self.package_name}.{self.msg_name}{{{modifier} {type} {name} = {id}}} 的类型指针为0，可能是未定义的类型。")
                else:
                    new = enum(self.elf, type_ptr).analy()
                    type = new.package_name + '.' + new.enum_name 
            
            self.modifier.append(modifier)      # 修饰符
            self.type.append(type)              # 类型
            self.name.append(name)              # 名称
            self.id.append(id)                  # ID
            
        return self
    
    def check_import(self):
        '''
            检查是否有import
        '''
        import_list = []
        for i in range(self.member_num):
            if '.' in self.type[i]:
                package_name, type_name = self.type[i].split('.', 1)
                
                if package_name != self.package_name:
                    # 如果包名不在当前包名中，是import的
                    import_list.append(package_name)
                else:
                    # 如果包名在当前包名中，是当前包的子消息或子枚举
                    self.type[i] = type_name
                    pass
        for i in self.child_message:
            import_list += i.check_import()
        return import_list
    
    def print(self, space='', file=sys.stdout):
        print(f"{space}message {self.msg_name}", file=file)
        print(f"{space}{{", file=file)
        
        # 打印子枚举
        for i in self.child_enum:
            i.print(space + '\t', file=file)
        
        # 打印子消息
        for i in self.child_message:
            i.print(space + '\t', file=file)
            
        # 打印元素
        for i in range(self.member_num):
            print(f"{space}\t{self.modifier[i]}{' 'if self.modifier[i] != '' else ''}{self.type[i]} {self.name[i]} = {self.id[i]};", file=file)
            
        print(f"{space}}}\n", file=file)
        pass

class protobuf_c:
    def __init__(self, elf_name, out_dir = '.', default_file_name = 'default'):
        
        message.content_direct  = {}
        message.content_list    = []
        enum.content_direct     = {}
        enum.content_list       = []
        
        self.proto_version  = 'proto2'      # 默认proto版本是proto2
        self.elf_name       = elf_name
        self.elf            = ELF(elf_name)
        
        self.package = {}                   # 包列表 {'package_name': [[enum1, enum2, ...], [message1, message2, ...]]}
        
        # 解析所有的MessageDescriptor地址
        message_addr = [int(hex_str, 16) for hex_str in self.analy_protobuf_c_message_unpack_param()]
        if len(message_addr) == 0:
            print(f"没有找到protobuf_c_message_unpack调用的参数地址，请检查文件 {self.elf_name} 是否正确。")
            return
        
        # 解析所有message
        for addr in message_addr:
            message(self.elf, addr).analy()
        
        # 检查proto版本
        proto_version = self.check_proto_version()
        if proto_version is not None:
            self.proto_version = proto_version
        
        # 建立enum的结构树
        for i in range(len(enum.content_list)-1, -1, -1):
            enum_item = enum.content_list[i]
            # 检查枚举名中是否存在.则需要将其移动到对应的包下
            if '.' in enum_item.enum_name:
                # 若存在，搜索对应的包名并移动
                before, sep, after = enum_item.enum_name.rpartition('.')
                # 只保留包名的后半部分
                enum_item.enum_name = after
                for j in range(len(message.content_list)):
                    if message.content_list[j].package_name == enum_item.package_name and message.content_list[j].msg_name == before:
                        # 找到对应的包名，将当前枚举移动到该包下
                        message.content_list[j].child_enum.append(enum_item)
                        enum.content_list.pop(i)
                        break
                    
        # 建立msg的结构树
        for i in range(len(message.content_list)-1, -1, -1):
            msg = message.content_list[i]
            # 检查消息名中是否存在.则需要将其移动到对应的包下
            if '.' in msg.msg_name:
                # 若存在，搜索对应的包名并移动
                before, sep, after = msg.msg_name.rpartition('.')
                # 只保留包名的后半部分
                msg.msg_name = after
                for j in range(len(message.content_list)):
                    if message.content_list[j].package_name == msg.package_name and message.content_list[j].msg_name == before:
                        # 找到对应的包名，将当前消息移动到该包下
                        message.content_list[j].child_message.append(msg)
                        message.content_list.pop(i)
                        break
        
        # 将所有枚举归类到对应的包中
        for i in enum.content_list:
            self.package.setdefault(i.package_name, [[], []])[0].append(i)
        # # 将所有消息归类到对应的包中
        for i in message.content_list:
            self.package.setdefault(i.package_name, [[], []])[1].append(i)
            
        # 设置特殊文件名
        if default_file_name in self.package.keys():
            log.error(f"包名 '{default_file_name}' 已经存在，无法作为文件名使用，请修改为其他名称。")
            return
        
        # 创建目录
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        if not out_dir.endswith('/'):
            out_dir += '/'
        
        # 写入文件
        for package_name, value in self.package.items():
            enums       = value[0]
            messages    = value[1]
            # 创建文件
            with open(out_dir + (package_name if package_name != '' else default_file_name) + '.proto', 'w', encoding='utf-8') as f:
                
                # 写入proto版本
                print(f"syntax = \"{self.proto_version}\";\n", file=f)
                
                # 写入包名
                if package_name != '':
                    print(f"package {package_name};\n", file=f)
                
                # 写入所有依赖
                import_list = []
                for msg in messages:
                    import_list += msg.check_import()
                # 写入依赖，同时去重
                if import_list != []:
                    for i in list(set(import_list)):
                        print(f"import \"{i + '.proto'}\";", file=f)
                    print(file=f)  # 换行
                    
                # 写入所有enum
                for e in enums:
                    e.print(file=f)
                    
                # 写入所有message
                for msg in messages:
                    msg.print(file=f)
        
    def analy_protobuf_c_message_unpack_param(self):
        '''
            提取protobuf_c_message_unpack调用的第一个参数地址
            objdump -d <file> | grep -B2 'call.*protobuf_c_message_unpack' | grep 'lea.*#' | cut -d'#' -f2 | awk '{print "0x" $1}'
        '''
        '''超简单的一行命令分析方法'''

        # 提取所有protobuf_c_message_unpack调用的第一个参数地址
        cmd = f"objdump -d {self.elf_name} | grep -B2 'call.*protobuf_c_message_unpack' | grep 'lea.*#' | cut -d'#' -f2 | awk '{{print \"0x\" $1}}'"
        result = os.popen(cmd).read()
        
        # 处理结果，提取地址
        message_addr = []
        for line in result.strip().split('\n'):
            if line.strip():
                message_addr.append(line.strip())

        return message_addr
    def check_proto_version(self):
        '''
            检查proto版本
        '''
        for msg in message.content_list:
            for modifier in msg.modifier:
                if modifier == '':
                    return 'proto3'
                else:
                    return 'proto2'
        return None

# 测试两个文件
if __name__ == '__main__':
    protobuf_c('./test/proto2/demo', 'test/proto2_t')    # proto2版本的测试文件
    protobuf_c('./test/proto3/demo', 'test/proto3_t')    # proto3版本的测试文件
    protobuf_c('./test/ciscn/ez_orw')   # 国赛题目的测试文件
