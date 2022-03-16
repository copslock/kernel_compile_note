# 无 kernel 源代码和 config 的情况下为 HG8120C 编译内核模块
https://blog.leexiaolan.tk/compile-kernel-module-for-hg8120c-without-source-and-config
<p>有读者在<a href="/persist-root-shell-and-perfect-solution-for-ipv6-package-loss-on-hg8120c-ont#disqus_thread" title="Tos's comment">评论区</a>留言说，想为光猫编译 ext2 文件系统内核模块，但是才执行 <code>insmod ext2.ko</code> 插入编译好的模块就出现 kernel panic。这个问题其实很早之前在我为光猫编译 <code>aufs</code> 模块就已经遇到了，下面就来说说如何解决这一问题。</p>
<h1>问题描述</h1>
<p>设备光猫 HG8120C 使用的 SOC 是 <code>Hisi sd511x</code>，运行 <code>linux v2.6.34.10</code> 内核，生产商不提供内核 GPL 源代码（至少我没有找到可以方便获取源代码的方式），因此缺失对应设备驱动，所以不能运行自行编译的内核。原厂内核不支持某些我们想要的特性，比如 <code>aufs</code> 或 <code>ext2</code> 等文件系统，我们能不能使用 <code>vanilla linux kernel</code> 的源代码来编译这些模块，使得这些模块可以顺利运行在原厂内核中？</p>
<p>理论上，和设备硬件驱动无关的模块是可以通过这样的方式编译并运行的。但是呢，可能因为模块依赖的某些函数没有导出，或者是被编译优化掉了，又或者 <code>CONFIG_*</code> 设置的原因，某些内核结构体少了一些字段，又或者厂商在内核中加入了私货，改变了结构体的布局或大小，等等等等，都可能导致使用这种方式编译的模块运行失败。厂商没有在 <code>/proc/config{,.gz}</code> 留下配置，这进一步加大了问题的难度。基于之前 <code>aufs</code> 的经验，我判断 <code>ext2</code> 有 90% 的概率也是可以顺利运行起来的。</p>
<h1>编译 ext2.ko</h1>
<p>在之前编译 <code>aufs</code> 的环境是，原始 <a href="https://www.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.34/linux-2.6.34.10.tar.xz" title="linux-2.6.34.10.tar.xz"><code>linux v2.6.34.10</code></a> 源代码，没有任何厂商夹带的私货，随便找了一个 <code>arm</code> 架构支持 <code>SMP</code> 板子的默认配置文件作为基础，编译 <code>aufs</code> 模块，加载的目标系统测试运行，panic 后修正某些 <code>CONFIG_*</code> 配置（后面将用 <code>loop.ko</code> 做例子来示范如何定位错误根源），重复“编译-&gt;测试-&gt;panic后修正”这个过程，直到测试成功。</p>
<p>在这个环境中，编译 <code>ext2.ko</code> 后，在目标设备上运行 <code>insmod ext2.ko</code> 后，一切正常，看起来设备已经支持 <code>ext2fs</code> 了。有这样的结果其实并不意外，因为在 <code>aufs</code> 的环境中，我已经修正了一些与文件系统有关的配置和厂商对结构体布局的修改。</p>
<pre><code>WAP(Dopra Linux) # modinfo ext2.ko
filename:       ext2.ko
description:    Second Extended Filesystem
author:         Remy Card and others
license:        GPL
vermagic:       2.6.34.10_sd5115v100_wr4.3 SMP mod_unload ARMv7
WAP(Dopra Linux) # insmod ext2.ko
WAP(Dopra Linux) # cat /proc/filesystems | grep ext2
        ext2
</code></pre>
<p>接下来就该测试挂载某个 <code>ext2</code> 文件系统的设备了，当然第一就想到了 <code>loop</code> 设备，但原厂内核不支持 <code>loop</code> 设备。没关系，我们继续编译一个 <code>loop.ko</code> 就行了。</p>
<pre><code>WAP(Dopra Linux) # insmod loop.ko
# kernel panic and device rebooted.
</code></pre>
<p>评论区那名读者遇到的类似问题出现啦！</p>
<h1>Debug loop.ko panic</h1>
<p>该如何 debug 这样的问题呢？幸运的是，厂商很“贴心”地为我们保存好了 panic 的很多信息，存放在 <code>/mnt/jffs2/panicinfo</code> 路径的文件里。</p>
<pre><code># after boot up again.
WAP(Dopra Linux) # cat /mnt/jffs2/panicinfo
Kernel panic - not syncing: Fatal exception
CPU: 0    Tainted: P      D W   (2.6.34.10_sd5115v100_wr4.3 #1)
Process insmod (pid: 1793, stack limit = 0xc25a2270)
PC is at c0092944
LR is at c0092b3c
pc : [&lt;c0092944&gt;]    lr : [&lt;c0092b3c&gt;]    psr: 60000013
sp : c25a3edc  ip : 00000000  fp : 00000000
r10: 4000ef74  r9 : c25a2000  r8 : bf898484
r7 : bf898434  r6 : bf898484  r5 : 00000000  r4 : c387ba00
r3 : 00000007  r2 : c035eac8  r1 : 00000000  r0 : 000000a0
Flags: nZCv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment user
[&lt;bf0c2a6c&gt;] (hw_ssp_get_backtrace_info+0x0/0x78 [hw_ssp_depend]) from [&lt;bf0c2bd0&gt;] (hw_ssp_write_panic_info+0xec/0x11c [hw_ssp_depend])
[&lt;bf0c2bd0&gt;] (hw_ssp_write_panic_info+0xec/0x11c [hw_ssp_depend]) from [&lt;c02e4368&gt;] (panic+0xa0/0x124)
[&lt;c02e4368&gt;] (panic+0xa0/0x124) from [&lt;c0030c94&gt;] (die+0x1b0/0x1d4)
[&lt;c0030c94&gt;] (die+0x1b0/0x1d4) from [&lt;c0033a2c&gt;] (__do_kernel_fault+0x64/0x84)
[&lt;c0033a2c&gt;] (__do_kernel_fault+0x64/0x84) from [&lt;c0033e0c&gt;] (do_page_fault+0x140/0x1e4)
[&lt;c0033e0c&gt;] (do_page_fault+0x140/0x1e4) from [&lt;c002c45c&gt;] (do_DataAbort+0x34/0x98)
[&lt;c002c45c&gt;] (do_DataAbort+0x34/0x98) from [&lt;c002cbcc&gt;] (__dabt_svc+0x4c/0x60)
[&lt;c002cbcc&gt;] (__dabt_svc+0x4c/0x60) from [&lt;c0092944&gt;] (bdi_register+0x8/0x13c)
[&lt;c0092944&gt;] (bdi_register+0x8/0x13c) from [&lt;bf898484&gt;] (0xbf898484)
</code></pre>
<p>从上面的 panic 信息可以看出，导致 panic 的原因是 data abort（从 <code>do_DataAbort</code> 可以猜想到），也就是通常的野指针问题。具体发生的位置在 <code>bdi_register</code> 很靠前的位置（bdi_register+0x8），基本就是头一两行代码的样子。至于最后的 <code>from [&lt;bf898484&gt;]</code> 这个值和寄存器 <code>LR</code> 相去甚远，就可以选择不用相信了。</p>
<p>找到 <code>bdi_register</code> 函数对应的源代码 <a href="http://elixir.free-electrons.com/linux/v2.6.34.10/source/mm/backing-dev.c#L538" title="mm/backing-dev.c#L538"><code>mm/backing-dev</code></a>，很容易确定是因为 545 行的 <code>bdi</code> 导致野指针异常。</p>
<pre><code>/* mm/backing-dev.c */
538 int bdi_register(struct backing_dev_info *bdi, struct device *parent,
539                 const char *fmt, ...)
540 {
541         va_list args;
542         int ret = 0;
543         struct device *dev;
544
545         if (bdi-&gt;dev)   /* The driver needs to use separate queues per device */
546                 goto exit;
547
548         va_start(args, fmt);
            ...
            ...
            ...
584         return ret;
585 }
586 EXPORT_SYMBOL(bdi_register);
587
588 int bdi_register_dev(struct backing_dev_info *bdi, dev_t dev)
589 {
590         return bdi_register(bdi, NULL, "%u:%u", MAJOR(dev), MINOR(dev));
591 }
592 EXPORT_SYMBOL(bdi_register_dev);
</code></pre>
<p>根据 <code>LR</code> 寄存器，追溯到 <code>bdi_register</code> 的调用者 <code>bdi_register_dev</code>，这之后的完整调用栈就只能靠猜了，剩下唯一能确定的就是调用栈最终应该回溯到 <code>loop.ko</code> 中的函数。</p>
<p>如果对内核相当熟悉，或者非常幸运（比如我），应该能很快梳理出完整的调用栈，如下：</p>
<pre><code>bdi_register
bdi_register_dev
add_disk
loop_init_one
loop_probe
</code></pre>
<p>函数 <code>bdi_register</code> 中引起的异常的 <code>bdi</code> 参数值来源于 <a href="http://elixir.free-electrons.com/linux/v2.6.34.10/source/block/genhd.c#L516" title="block/genhd.c#L516"><code>add_disk</code></a>，549 行 <code>bdi = &amp;disk-&gt;queue-&gt;backing_dev_info;</code>。</p>
<pre><code>/* block/genhd.c */
516 void add_disk(struct gendisk *disk)
517 {
518         struct backing_dev_info *bdi;
            ...
            ...
            ...
546         register_disk(disk);
547         blk_register_queue(disk);
548
549         bdi = &amp;disk-&gt;queue-&gt;backing_dev_info;
550         bdi_register_dev(bdi, disk_devt(disk));
551         retval = sysfs_create_link(&amp;disk_to_dev(disk)-&gt;kobj, &amp;bdi-&gt;dev-&gt;kobj,
552                                    "bdi");
553         WARN_ON(retval);
554 }
</code></pre>
<p>函数 <code>add_disk</code> 是编译在内核中，可以通过查看其汇编代码来确定 <code>queue</code> 和 <code>backing_dev_info</code> 成员在结构体中的偏移量。</p>
<p><img alt="原始内核中结构体成员的偏移量" src="/media/ag5zfmJsb2ctbGVlLWhyZHISCxIFTWVkaWEYgICAgJmZjQoM/offset-in-add_disk-of-kernel.png" /></p>
<p>从上图高亮的汇编代码中可以看出，<code>queue</code> 偏移量是 <code>0x11c</code>，<code>backing_dev_info</code> 的偏移量是 <code>0xa0</code>。这是在原始厂商的内核中的偏移值。再来看看我们编译的 <code>loop.ko</code> 中的偏移值。由于是我们自行编译的，获取这些信息相对比较容易。只需要在编译时配置 <code>CONFIG_DEBUG_INFO=y</code> 后，使用 <code>pahole</code> 就能获取这些信息。</p>
<pre><code>leexiaolan@mars:~/linux-2.6.34.10$ pahole -C gendisk drivers/block/loop.ko
struct gendisk {
        int                        major;                /*     0     4 */
        int                        first_minor;          /*     4     4 */
        int                        minors;               /*     8     4 */
        char                       disk_name[32];        /*    12    32 */
        char *                     (*devnode)(struct gendisk *, mode_t *); /*    44     4 */
        struct disk_part_tbl *     part_tbl;             /*    48     4 */

        /* XXX 4 bytes hole, try to pack */

        struct hd_struct           part0;                /*    56   336 */
        /* --- cacheline 6 boundary (384 bytes) was 8 bytes ago --- */
        const struct block_device_operations  * fops;    /*   392     4 */
        struct request_queue *     queue;                /*   396     4 */
        ...
        ...
}
</code></pre>
<p><code>queue</code> 成员偏移量是 <code>396</code>，转换成 16 进制是 <code>0x18c</code>，和原始内核中的偏移量 <code>0x11c</code> 多了 <code>0x70</code>，所以位于 <code>queue</code> 前面的大小为 <code>336</code> 的 <code>part0</code> 就很可疑了。继续深挖 <code>struct hd_struct part0</code>。</p>
<pre><code>leexiaolan@mars:~/linux-2.6.34.10$ pahole -C hd_struct drivers/block/loop.ko
struct hd_struct {
        sector_t                   start_sect;           /*     0     4 */
        sector_t                   nr_sects;             /*     4     4 */
        sector_t                   alignment_offset;     /*     8     4 */
        unsigned int               discard_alignment;    /*    12     4 */
        struct device              __dev;                /*    16   280 */
        /* --- cacheline 4 boundary (256 bytes) was 40 bytes ago --- */
        struct kobject *           holder_dir;           /*   296     4 */
        int                        policy;               /*   300     4 */
        int                        partno;               /*   304     4 */
        long unsigned int          stamp;                /*   308     4 */
        int                        in_flight[2];         /*   312     8 */
        /* --- cacheline 5 boundary (320 bytes) --- */
        struct disk_stats *        dkstats;              /*   320     4 */
        struct rcu_head            rcu_head;             /*   324     8 */

        /* size: 336, cachelines: 6, members: 12 */
        /* padding: 4 */
        /* last cacheline: 16 bytes */
};
</code></pre>
<p>这回可疑的是 <code>struct device __dev</code>。</p>
<pre><code>leexiaolan@mars:~/linux-2.6.34.10$ pahole -C device drivers/block/loop.ko
struct device {
        struct device *            parent;               /*     0     4 */
        struct device_private *    p;                    /*     4     4 */
        struct kobject             kobj;                 /*     8    36 */
        const char  *              init_name;            /*    44     4 */
        struct device_type *       type;                 /*    48     4 */
        struct semaphore           sem;                  /*    52    16 */
        /* --- cacheline 1 boundary (64 bytes) was 4 bytes ago --- */
        struct bus_type *          bus;                  /*    68     4 */
        struct device_driver *     driver;               /*    72     4 */
        void *                     platform_data;        /*    76     4 */
        struct dev_pm_info         power;                /*    80   120 */
        /* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
        ...
        ...
}
</code></pre>
<p><code>power</code> 的大小很可疑，我们来看看 <a href="http://elixir.free-electrons.com/linux/v2.6.34.10/source/include/linux/pm.h#L451" title="include/linux/pm.h#L451"><code>struct dev_pm_info</code></a> 在头文件中的定义，一眼就可以发现其中有两个 <code>CONFIG_*</code> 控制的宏，检查 <code>.config</code> 文件，发现这两配置确实是打开的，估计这就是罪魁祸首。</p>
<pre><code>451 struct dev_pm_info {
452         pm_message_t            power_state;
453         unsigned int            can_wakeup:1;
454         unsigned int            should_wakeup:1;
455         unsigned                async_suspend:1;
456         enum dpm_state          status;         /* Owned by the PM core */
457 #ifdef CONFIG_PM_SLEEP
458         struct list_head        entry;
459         struct completion       completion;
460 #endif
461 #ifdef CONFIG_PM_RUNTIME
462         struct timer_list       suspend_timer;
463         unsigned long           timer_expires;
464         struct work_struct      work;
465         wait_queue_head_t       wait_queue;
466         spinlock_t              lock;
467         atomic_t                usage_count;
468         atomic_t                child_count;
469         unsigned int            disable_depth:3;
470         unsigned int            ignore_children:1;
471         unsigned int            idle_notification:1;
472         unsigned int            request_pending:1;
473         unsigned int            deferred_resume:1;
474         unsigned int            run_wake:1;
475         unsigned int            runtime_auto:1;
476         enum rpm_request        request;
477         enum rpm_status         runtime_status;
478         int                     runtime_error;
479 #endif
480 };
</code></pre>
<p>关掉 <code>CONFIG_PM_SLEEP</code> 和 <code>CONFIG_PM_RUNTIME</code> 这两个配置，重新编译 <code>loop.ko</code>，再来检查 <code>queue</code> 的偏移量：</p>
<pre><code>leexiaolan@mars:~/linux-2.6.34.10$ pahole -C gendisk drivers/block/loop.ko|grep queue
        struct request_queue *     queue;                /*   284     4 */
</code></pre>
<p>284 == 0x11c，已经和原始内核中的偏移量保持一致，可以到设备上进行测试了。</p>
<h1>测试 loop.ko 和 ext2.ko</h1>
<pre><code>WAP(Dopra Linux) # insmod loop.ko
WAP(Dopra Linux) # mkdir ext2-mount-test
WAP(Dopra Linux) # mount -t ext2 -o loop ext2.img ext2-mount-test
WAP(Dopra Linux) # cd ext2-mount-test
WAP(Dopra Linux) # &gt; test.txt echo 'ext2 fs create/write test.'; ls
lost+found/ test.txt
WAP(Dopra Linux) # cat test.txt
ext2 fs create/write test.
WAP(Dopra Linux) # rm test.txt; ls
lost+found/
</code></pre>
<p>看起来是一切正常了。<code>ext2.ko</code> 和 <code>loop.ko</code> 能够正常运行的 <a href="https://github.com/LeeXiaolan/hwfw-tool/tree/master/linux-2.6.34.10" title="config and patches"><code>config</code> 文件和补丁</a>，适用于 <a href="https://www.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.34/linux-2.6.34.10.tar.xz" title="linux-2.6.34.10.tar.xz">linux-2.6.34.10</a>。顺带一提，<code>xt_hashlimit.ko</code> 也可以正常运行。</p>
<h1>结论</h1>
<p>上述因为 <code>CONFIG_*</code> 引起的结构体内存布局差异定位起来还是比较容易的，而刚好上面的例子中差异很大，更容易定位。而另一种因为厂商夹带私货引起的内存布局差异，就需要比对更多的成员偏移来精确定位和补丁。</p>
<p>模块和内核之间交互就是通过一组导出函数和各种内核对象进行的。导出函数缺失在加载模块时就能被发现，直接后果就是加载内核模块失败。而内核对象的内存布局，只有到运行时才能发现错误。故只要保证内核对象的内存布局一致，在没有源代码和对应 <code>config</code> 文件的情况下，使用 <code>out-of-tree</code> 来编译某些内核模块是完全可行的。</p>

      
