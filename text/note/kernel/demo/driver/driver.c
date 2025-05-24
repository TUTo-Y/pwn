#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

char buffer[0x1000] = {0};
size_t size;

int my_open(struct inode *inode, struct file *file)
{
    return 0;
}
int my_release(struct inode *inode, struct file *file)
{
    return 0;
}
ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    char tmp[0x10];
    copy_from_user(buffer, buf, count);
    size = count;

    asm volatile (
        "lea rdi, [rsp];"
        "lea rsi, [buffer];"
        "mov rcx, [size];"
        "rep movsb" 
    );
    return 0;
}
ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
    return 0;
}
ssize_t my_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
    case 0:
        break;
    }
    return 0;
}

static struct file_operations my_proc_ops = {
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = my_ioctl,
    .compat_ioctl = my_ioctl};
static struct proc_dir_entry *my_proc_dir_entry;
static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR, // 动态分配次设备号
    .name = "driver",            // /dev 下的设备名称
    .fops = &my_proc_ops,        // 文件操作
};

static int __init my_driver_init(void)
{
    int ret;
    printk(KERN_INFO "驱动被加载...\n");

    // 创建 /proc 文件
    my_proc_dir_entry = proc_create("driver", 0666, NULL, &my_proc_ops);
    if (IS_ERR(my_proc_dir_entry))
    {
        printk(KERN_ERR "创建proc文件失败\n");
        return PTR_ERR(my_proc_dir_entry);
    }

    // 注册 miscdevice
    ret = misc_register(&my_misc_device);
    if (ret)
    {
        printk(KERN_ERR "注册 miscdevice 失败\n");
        proc_remove(my_proc_dir_entry);
        return ret;
    }
    return 0;
}

static void __exit my_driver_exit(void)
{
    printk(KERN_INFO "驱动被卸载...\n");

    // 移除 /proc 文件
    proc_remove(my_proc_dir_entry);

    // 注销 miscdevice
    misc_deregister(&my_misc_device);
}

module_init(my_driver_init);
module_exit(my_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TUTo");
MODULE_DESCRIPTION("内核驱动示例");
MODULE_VERSION("0.1");