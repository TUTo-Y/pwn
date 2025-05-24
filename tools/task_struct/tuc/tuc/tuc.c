#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/kallsyms.h>

static int driver_loaded = 0; // 标志变量，防止重复加载

int my_open(struct inode *inode, struct file *file)
{
    return 0;
}
int my_release(struct inode *inode, struct file *file)
{
    return 0;
}

ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    return 0;
}

/**
 * \brief 控制进程的SIGNAL_UNKILLABLE
 * \param cmd 1表示添加flag, 0表示删除flag
 * \return 0成功，-1失败
 */
ssize_t my_ioctl(struct file *file, unsigned int cmd, unsigned long id)
{
    struct task_struct *task;
    pid_t pid;

    pid = id;

    // 遍历所有进程
    for_each_process(task)
    {
        // 查找进程
        if (task->pid == pid)
        {
            if (cmd)
                task->signal->flags |= SIGNAL_UNKILLABLE;
            else
                task->signal->flags &= ~SIGNAL_UNKILLABLE;

            return 0;
        }
    }
    return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops my_proc_ops = {
    .proc_open = my_open,
    .proc_release = my_release,
    .proc_read = my_read,
    .proc_ioctl = my_ioctl,
    .proc_compat_ioctl = my_ioctl,
};
#else
static struct file_operations my_proc_ops = {
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .unlocked_ioctl = my_ioctl,
    .compat_ioctl = my_ioctl,
};
#endif

static struct proc_dir_entry *my_proc_dir_entry;
// 为 miscdevice 定义单独的 file_operations
static struct file_operations my_misc_fops = {
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .unlocked_ioctl = my_ioctl,
    .compat_ioctl = my_ioctl,
};

static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR, // 动态分配次设备号
    .name = "tuc",               // /dev 下的设备名称
    .fops = &my_misc_fops,       // 文件操作
};

static int __init my_driver_init(void)
{
    int ret;

    // 检查是否已经加载
    if (driver_loaded)
    {
        printk(KERN_ERR "驱动已加载，禁止重复加载\n");
        return -EBUSY; // 返回忙状态
    }

    printk(KERN_INFO "驱动被加载...\n");

    // 创建 /proc 文件
    my_proc_dir_entry = proc_create("tuc", 0666, NULL, &my_proc_ops);
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

    driver_loaded = 1; // 标记驱动已加载
    return 0;
}

static void __exit my_driver_exit(void)
{
    printk(KERN_INFO "驱动被卸载...\n");

    // 移除 /proc 文件
    if (my_proc_dir_entry)
        proc_remove(my_proc_dir_entry);

    // 注销 miscdevice
    if (driver_loaded)
        misc_deregister(&my_misc_device);

    driver_loaded = 0; // 清除标记
}

module_init(my_driver_init);
module_exit(my_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TUTo");
MODULE_DESCRIPTION("tuc不死守护进程");
MODULE_VERSION("0.1");