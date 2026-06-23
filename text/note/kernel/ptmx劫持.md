# ptmx劫持

有一个伪终端设备`/dev/ptmx`

在我们打开这个设备时内核中会创建一个 `tty_struct` 结构体，与其他类型设备相同，tty驱动设备中同样存在着一个存放着函数指针的结构体 `tty_operations`

如果我们可以修改`tty_struct->ops`指向`fake_tty_operations`，那么在操作这个终端(read,write,ioctl)时就会指向我们的恶意函数

## 结构体

```C
// include/linux/tty.h
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;	/* class device or NULL (e.g. ptys, serdev) */
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;

	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;

	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	char name[64];
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */

	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		unsigned long unused[0];
	} __aligned(sizeof(unsigned long)) flow;

	struct {
		spinlock_t lock;
		struct pid *pgrp;
		struct pid *session;
		unsigned char pktstatus;
		bool packet;
		unsigned long unused[0];
	} __aligned(sizeof(unsigned long)) ctrl;

	int hw_stopped;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;

	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;		/* protects tty_files list */
	struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
} __randomize_layout;

// include/linux/tty_driver.h 
struct tty_operations {
	struct tty_struct * (*lookup)(  struct tty_driver *driver,
			                        struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	unsigned int (*write_room)(struct tty_struct *tty);
	unsigned int (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);
	int  (*get_serial)(struct tty_struct *tty, struct serial_struct *p);
	int  (*set_serial)(struct tty_struct *tty, struct serial_struct *p);
	void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

## struct tty_struct 大小查找方法

### 静态分析

1. 利用`vmlinux-to-elf`修补`vmlinux`

```bash
vmlinux-to-elf ./vmlinux ./vmlinux.elf
```

2. 利用IDA，在alloc_tty_struct函数中，存在一条内存分配代码，即可知道大小为0x2E0

```
 (_DWORD *)kmem_cache_alloc_trace(qword_FFFFFFFF821C4450, 37781696LL, 0x2E0LL);
```

### 动态分析

查找符号`alloc_tty_struct`找到后动调搜索函数内容即可，步骤如上
