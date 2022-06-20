#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/rhashtable.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/poll.h>
#include <linux/binfmts.h>
#include <linux/compat.h>
#include <linux/cdev.h>
#include <linux/kprobes.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include "logger.h"

#define DEFAULT_BUFFER_SIZE 4096

int enable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    if(pte->pte &~_PAGE_RW){
        pte->pte |=_PAGE_RW;
    }
    return 0;
}

int disable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
    return 0;
}

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)
typedef unsigned long (*kallsyms_lookup_name_p)(const char* kallsyms_name);

static struct kprobe kp0, kp1;
static uint64_t  kallsyms_lookup_name_addr = 0;
static kallsyms_lookup_name_p kallsyms_lookup_name_func = NULL;

KPROBE_PRE_HANDLER(handler_pre0) {
    kallsyms_lookup_name_addr = (--regs->ip);
    return 0;
}

KPROBE_PRE_HANDLER(handler_pre1) {
    return 0;
}

static int do_register_kprobe(struct kprobe* kp, char* symbol_name, void* handler) {
    int ret;

    kp->symbol_name = symbol_name;
    kp->pre_handler = handler;

    ret = register_kprobe(kp);
    if (ret < 0) {
        FATAL("do_register_kprobe: failed to register for symbol %s, returning %d\n", symbol_name, ret);
        return ret;
    }

    INFO("planted krpobe for symbol %s at %p\n", symbol_name, kp->addr);

    return ret;
}

int callsym_getter_init(void) {
    if (kallsyms_lookup_name_func != NULL)
        return 0;

    int status;
    status = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);

    if (status < 0) return status;

    status = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);

    if (status < 0) {
        // cleaning initial krpobe
        unregister_kprobe(&kp0);
        return status;
    }

    unregister_kprobe(&kp0);
    unregister_kprobe(&kp1);

    INFO("kallsyms_lookup_name address = 0x%llx\n", kallsyms_lookup_name_addr);
    kallsyms_lookup_name_func = (kallsyms_lookup_name_p)kallsyms_lookup_name_addr;
    return 0;
}

void* get_callsym_by_name(const char* callsym_name) {
    if (kallsyms_lookup_name_func == NULL) {
        return NULL;
    }

    return (void*)kallsyms_lookup_name_func(callsym_name);
}

typedef int (*syscall_t)(struct pt_regs*);

int pec_execve(struct pt_regs *args);

static struct {
    struct filename* (*getname)(const char*);
    void (*putname)(struct filename *name);
    syscall_t original_execve;
    syscall_t *syscall_table;
    int (*kernel_execve)(const char *, const char *const *, const char *const *);
    struct file* (*alloc_file_clone)(struct file *, int, const struct file_operations *);
} pec_symbols;


typedef struct pec_ring_buffer {
    u32 payload_len;
    u8 *head;
    u8 *tail;
    u8 *payload_head;
    u8 *payload_tail;
    size_t size;
} pec_ring_buffer_t;

static void pec_ring_buffer_init(pec_ring_buffer_t* dst, size_t size) {
    dst->head = vmalloc(size);
    dst->payload_head = dst->payload_tail = dst->head;
    dst->tail = dst->head + size;
    dst->payload_len = 0;
    dst->size = size;
}

static int pec_ring_buffer_read(pec_ring_buffer_t* src, u8* dst, u32 len) {
    if(src->payload_len == 0) return 0;

    if(len > src->payload_len) len = src->payload_len;

    if(src->payload_head + len > src->tail) {
        int len1 = src->tail - src->payload_head;
        int len2 = len - len1;
        copy_to_user(dst, src->payload_head, len1);
        copy_to_user(dst + len1, src->head, len2);
        src->payload_head = src->head + len2;
    } else {
        copy_to_user(dst, src->payload_head, len);
        src->payload_head = src->payload_head + len;
    }
    src->payload_len -= len;

    return len;
}

static int pec_ring_buffer_read_internal(pec_ring_buffer_t* src, u8* dst, u32 len) {
    if (src->payload_len == 0) return 0;

    if (len > src->payload_len) len = src->payload_len;

    if (src->payload_head + len > src->tail) {
        int len1 = src->tail - src->payload_head;
        int len2 = len - len1;
        memcpy(dst, src->payload_head, len1);
        memcpy(dst + len1, src->head, len2);
        src->payload_head = src->head + len2;
    } else {
        memcpy(dst, src->payload_head, len);
        src->payload_head = src->payload_head + len;
    }
    src->payload_len -= len;

    return len;
}

static int pec_ring_buffer_write(pec_ring_buffer_t* dst, const u8* src, u32 src_str_len) {
    if (src_str_len > dst->size - dst->payload_len) {
        struct pec_ring_buffer new_buffer;
        pec_ring_buffer_init(&new_buffer, dst->size * 2);
        new_buffer.payload_len = dst->payload_len;
        pec_ring_buffer_read_internal(dst, new_buffer.head, dst->payload_len);
        new_buffer.payload_tail += new_buffer.payload_len;
        vfree(dst->head);
        *dst = new_buffer;
    }

    if (dst->payload_tail + src_str_len > dst->tail) {
        int len1 = dst->tail - dst->payload_tail;
        int len2 = src_str_len - len1;
        copy_from_user(dst->payload_tail, src, len1);
        copy_from_user(dst->head, src + len1, len2);
        dst->payload_tail = dst->head + len2;
    } else {
        copy_from_user(dst->payload_tail, src, src_str_len);
        dst->payload_tail += src_str_len;
    }

    if (dst->payload_len + src_str_len > dst->size) {
        int move_len = dst->payload_len + src_str_len - dst->size;
        if(dst->payload_head + move_len > dst->tail) {
            int len1 = dst->tail - dst->payload_head;
            int len2 = move_len - len1;
            dst->payload_head = dst->head + len2;
        } else
            dst->payload_head = dst->payload_head + move_len;

        dst->payload_len = dst->size;
    } else {
        dst->payload_len += src_str_len;
    }

    return 0;
}

static void  pec_ring_buffer_destroy(pec_ring_buffer_t* dst) {
    vfree(dst->head);
}

typedef enum pec_entity {
    UNDEFINED = 0,
    PROXY_PROCESS,
    SERVICE,
    SERVICE_WORKER
} pec_entity_t;

typedef struct program_args {
    char* file;
    char** arg;
    char** envp;
} program_args_t;


struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};


// from fs/exec.c
static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat)) {
        compat_uptr_t compat;

        if (get_user(compat, argv.ptr.compat + nr))
            return ERR_PTR(-EFAULT);

        return compat_ptr(compat);
    }
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */
static int count(struct user_arg_ptr argv, int max)
{
    int i = 0;

    if (argv.ptr.native != NULL) {
        for (;;) {
            const char __user *p = get_user_arg_ptr(argv, i);

            if (p == NULL)
                break;

            if (IS_ERR(p))
                return -EFAULT;

            if (i >= max)
                return -E2BIG;
            ++i;

            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
            cond_resched();
        }
    }
    return i;
}

void destroy_program_args(program_args_t *dst) {
    if (dst == NULL)
        return;
    if (dst->file != NULL)
        vfree(dst->file);
    if (dst->arg != NULL) {
        size_t i;
        for (i = 0; dst->arg[i] != NULL; i++)
            vfree(dst->arg);
        vfree(dst->arg);
    }
    if (dst->envp != NULL) {
        size_t i;
        for (i = 0; dst->envp[i] != NULL; i++)
            vfree(dst->envp);
        vfree(dst->envp);
    }

    vfree(dst);
}

program_args_t* new_program_args(const char __user *path, const char __user *const args[], const char __user *const *envp,
                                 struct filename* (*getname)(const char*), void (*putname)(struct filename *name)) {
    program_args_t* pr_args = vzalloc(sizeof(program_args_t));
    if (pr_args == NULL)
        return NULL;
    struct filename* fname = getname(path);
    pr_args->file = vzalloc(strlen(fname->name + 1));
    strcpy(pr_args->file, fname->name);

    struct user_arg_ptr argv = { .ptr.native = args };
    struct user_arg_ptr envs = { .ptr.native = envp };
    int retval = count(argv, MAX_ARG_STRINGS);
    INFO("filename=%s, argv_count=%d", pr_args->file, retval);
    if (retval < 0)
        goto OUT_FREE;

    pr_args->arg = vzalloc(sizeof(char*) * retval + 1);
    if (copy_from_user(pr_args->arg, args, sizeof(char*) * retval) < 0) {
        ERROR("copy argv error");
        goto OUT_FREE;
    }
    INFO("copy argv success");
    size_t i;
    for (i = 0; i < retval; i++) {
        const char* tmp = pr_args->arg[i];
        ssize_t strlen = strnlen_user(tmp, MAX_ARG_STRLEN);
        if (strlen == 0)
            break;
        if (strlen < 0) {
            ERROR("bad strlen")
            goto OUT_FREE;
        }
        pr_args->arg[i] = vzalloc(sizeof(char) * strlen + 1);
        if (copy_from_user(pr_args->arg[i], tmp, sizeof(char) * strlen) < 0) {
            ERROR("copy argv element error");
            goto OUT_FREE;
        }
        if (pr_args->arg[i] != NULL)
            INFO("file=%s argv[%lu] = %s",pr_args->file,i, pr_args->arg[i]);
    }

    retval = count(envs, MAX_ARG_STRINGS);
    INFO("filename=%s, env_count=%d", pr_args->file, retval);
    if (retval < 0)
        goto OUT_FREE;
    pr_args->envp = vzalloc(sizeof(char*) * retval + 1);
    if (copy_from_user(pr_args->envp, args, sizeof(char*) * retval) < 0) {
        ERROR("copy envp error");
        goto OUT_FREE;
    }
    INFO("copy envp success");
    for (i = 0; i < retval; i++) {
        const char* tmp = pr_args->envp[i];
        ssize_t strlen = strnlen_user(tmp, MAX_ARG_STRLEN);
        if (strlen == 0)
            break;
        if (strlen < 0) {
            ERROR("bad strlen")
            goto OUT_FREE;
        }
        pr_args->envp[i] = vzalloc(sizeof(char) * strlen + 1);
        if (copy_from_user(pr_args->envp[i], tmp, sizeof(char) * strlen) < 0) {
            ERROR("copy envp element error");
            goto OUT_FREE;
        }
        if (pr_args->envp[i] != NULL)
            INFO("file=%s envp[%lu] = %s",pr_args->file, i, pr_args->envp[i]);
    }
    return pr_args;
    OUT_FREE:
    destroy_program_args(pr_args);
    return NULL;
}

typedef struct dummy_file dummy_file_t;
typedef struct proxy proxy_t;
typedef struct service service_t;


struct dummy_file{
    char* fname;
    size_t ID;
    service_t* service;
    struct rhash_head head;
};

static dummy_file_t* new_dummy_file(char* fname, size_t ID, service_t* service) {
    dummy_file_t* dummy_file = vmalloc(sizeof(dummy_file_t));
    dummy_file->fname = fname;
    dummy_file->ID = ID;
    dummy_file->service = service;
    return dummy_file;
}

static void dummy_file_destroy(dummy_file_t* dummy_file, void*) {
    vfree(dummy_file->fname);
    vfree(dummy_file);
}

struct proxy {
    size_t ID;
    service_t* service;
    pec_ring_buffer_t stdin_buffer;
    pec_ring_buffer_t stdout_buffer;
    wait_queue_head_t stdin_wait;
    wait_queue_head_t stdout_wait;
    wait_queue_head_t ioctl_wait;
    spinlock_t stdin_buffer_lock;
    spinlock_t stdout_buffer_lock;
    program_args_t* program_args;
    atomic_t ret_code_ready;
    int ret_code;
    size_t dummy_file_ID;
    struct rhash_head head;
};

static proxy_t* new_proxy(size_t ID, service_t *service, program_args_t* args, size_t dummy_file_ID) {
    proxy_t* proxy = vmalloc(sizeof(proxy_t));
    proxy->ID = ID;
    proxy->service = service;
    proxy->program_args = args;
    pec_ring_buffer_init(&proxy->stdin_buffer, DEFAULT_BUFFER_SIZE);
    pec_ring_buffer_init(&proxy->stdout_buffer, DEFAULT_BUFFER_SIZE);
    init_waitqueue_head(&proxy->stdin_wait);
    init_waitqueue_head(&proxy->stdout_wait);
    init_waitqueue_head(&proxy->stdout_wait);
    spin_lock_init(&proxy->stdin_buffer_lock);
    spin_lock_init(&proxy->stdout_buffer_lock);
    proxy->ret_code_ready.counter = 0;
    proxy->ret_code = 0;
    proxy->dummy_file_ID = dummy_file_ID;
    return proxy;
}

static void proxy_destroy(proxy_t* dst, void*) {
    destroy_program_args(dst->program_args);
    spin_lock(&dst->stdin_buffer_lock);
    spin_lock(&dst->stdout_buffer_lock);
    pec_ring_buffer_destroy(&dst->stdin_buffer);
    pec_ring_buffer_destroy(&dst->stdout_buffer);
}

typedef struct raw_proxy_queue {
    struct list_head queue_list;
    proxy_t* proxy;
} raw_proxy_queue_t;

static void  raw_proxy_queue_init(raw_proxy_queue_t* dst) {
    INIT_LIST_HEAD_RCU(&dst->queue_list);
}

static void raw_proxy_queue_push(raw_proxy_queue_t* dst, proxy_t* proxy) {
    raw_proxy_queue_t* node = vmalloc(sizeof(raw_proxy_queue_t));
    node->proxy = proxy;
    list_add_tail_rcu(&node->queue_list, &dst->queue_list);
}

static proxy_t* raw_proxy_queue_pop(raw_proxy_queue_t* dst) {
    raw_proxy_queue_t* node = list_first_entry(&dst->queue_list, raw_proxy_queue_t, queue_list);
    list_del_rcu(&node->queue_list);
    proxy_t* proxy = node->proxy;
    vfree(node);
    return proxy;
}

static bool raw_proxy_queue_is_empty(const raw_proxy_queue_t* src) {
    return list_empty(&src->queue_list);
}

struct service {
    size_t ID;
    wait_queue_head_t ioctl_wait;
    raw_proxy_queue_t row_proxy_queue;
    struct rhash_head head;
};

service_t* new_service(size_t ID) {
    service_t* service = vmalloc(sizeof(service_t));
    service->ID = ID;
    init_waitqueue_head(&service->ioctl_wait);
    raw_proxy_queue_init(&service->row_proxy_queue);
    return service;
}

void service_destroy(service_t* service, void*) {
    vfree(service);
}

typedef struct pec_storage {
    struct rhashtable dummy_files;
    struct rhashtable services;
    struct rhashtable proxy;
    rwlock_t dummy_file_lock;
    rwlock_t services_lock;
    rwlock_t proxy_lock;
} pec_storage_t;

static struct {
    atomic_long_t dummy_file_id;
    atomic_long_t service_id;
    atomic_long_t proxy_id;
} pec_id_counters = {{0}, {0}, {0}};

static u32 string_hash(const void *data, u32, u32) {
    const char* str = (const char*)data;
    const int p = 53;
    const int m = 912239431;
    u32 hash_value = 0;
    long long p_pow = 1;
    size_t i;
    for (i = 0; str[i] != '\0'; i++) {
        hash_value = (hash_value + (str[i] - 'a' + 1) * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash_value;
}

static u32 dummy_file_hash(const void *data, u32 len, u32 seed) {
    const dummy_file_t* dummy_file = data;
    return string_hash(dummy_file->fname, len, seed);
}

static int dummy_file_cmp(struct rhashtable_compare_arg *arg,
                   const void *obj) {
    return strcmp((const char*)arg->key, ((dummy_file_t*)obj)->fname);
}

static struct rhashtable_params dummy_file_param = {
        .key_offset = offsetof(dummy_file_t, fname),
        .head_offset = offsetof(dummy_file_t, head),
        .obj_cmpfn = dummy_file_cmp,
        .hashfn = string_hash,
        .obj_hashfn = dummy_file_hash,
        .min_size = 16
};

static struct rhashtable_params service_params = {
        .key_len = sizeof(size_t),
        .key_offset = offsetof(service_t, ID),
        .head_offset = offsetof(service_t, head),
};

static struct rhashtable_params proxy_params = {
        .key_len = sizeof(size_t),
        .key_offset = offsetof(proxy_t , ID),
        .head_offset = offsetof(proxy_t , head),
};

dummy_file_t* pec_storage_create_dummy_file(pec_storage_t* dst, const char* fname) {
    dummy_file_t* dummy_file = new_dummy_file(fname, atomic_long_inc_return(&pec_id_counters.dummy_file_id), NULL);

    int ret = rhashtable_insert_fast(&dst->dummy_files, &dummy_file->head, dummy_file_param);
    if (ret != 0) {
        dummy_file_destroy(dummy_file, NULL);
        return NULL;
    }

    return dummy_file;
}

service_t * pec_storage_create_service(pec_storage_t* dst) {
    service_t* service = new_service(atomic_long_inc_return(&pec_id_counters.service_id));
    service_t* old = rhashtable_lookup_get_insert_fast(&dst->services, &service->head, service_params);
    if (old != NULL) {
        service_destroy(service, NULL);
        return NULL;
    }
    return service;
}

service_t * pec_storage_find_service_by_id(pec_storage_t* dst, size_t ID) {
    service_t* service = rhashtable_lookup_fast(&dst->services, &ID, service_params);
    return service;
}

proxy_t* pec_storage_create_proxy(pec_storage_t* dst, service_t* service, program_args_t* args, size_t dummy_file_ID) {
    proxy_t* proxy = new_proxy(atomic_long_inc_return(&pec_id_counters.proxy_id), service, args, dummy_file_ID);
    proxy_t* old = rhashtable_lookup_get_insert_fast(&dst->proxy, &proxy->head, proxy_params);
    if (old != NULL) {
        proxy_destroy(proxy, NULL);
        return NULL;
    }
    return proxy;
}

proxy_t* pec_storage_find_proxy_by_id(pec_storage_t* dst, size_t ID) {
    return rhashtable_lookup_fast(&dst->proxy, &ID, proxy_params);
}

dummy_file_t * pec_storage_find_dummy_file_by_fnmae(pec_storage_t* dst, const char* fname) {
    dummy_file_t* dummy_file= rhashtable_lookup_fast(&dst->dummy_files, fname, dummy_file_param);
    return dummy_file;
}

static pec_storage_t storage;
void pec_store_init(void) {
    rhashtable_init(&storage.dummy_files, &dummy_file_param);
    rhashtable_init(&storage.services, &service_params);
    rhashtable_init(&storage.proxy, &proxy_params);
    rwlock_init(&storage.dummy_file_lock);
    rwlock_init(&storage.services_lock);
    rwlock_init(&storage.proxy_lock);
}

void pec_destroy(void) {
    rhashtable_free_and_destroy(&storage.dummy_files, (void (*)(void *, void *)) dummy_file_destroy, NULL);
    rhashtable_free_and_destroy(&storage.services, (void (*)(void *, void *)) service_destroy, NULL);
    rhashtable_free_and_destroy(&storage.proxy, (void (*)(void *, void *)) proxy_destroy, NULL);
}
#define PATH_TO_PROXY "/home/amamedov/dev/university/final/proxy-exec/cmake-build-debug/bin/pec-proxy"

int pec_execve(struct pt_regs *args) {
    struct filename* fln = pec_symbols.getname((const char*)args->di);
    service_t * service = NULL;

    dummy_file_t* dummy_file = pec_storage_find_dummy_file_by_fnmae(&storage, fln->name);
    if (dummy_file == NULL) {
        return pec_symbols.original_execve(args);
    }
    pec_symbols.putname(fln);
    service = dummy_file->service;
    program_args_t* pg = new_program_args((const char*)args->di, (const char* const*) args->si, (const char* const*)args->dx, pec_symbols.getname, pec_symbols.putname);

    proxy_t* proxy = pec_storage_create_proxy(&storage, service, pg, dummy_file->ID);

    INFO("a request was made to execute the file %s, an id=%lu was assigned to the proxy process", pg->file, proxy->ID);
    char c_str_number[15];
    memset(c_str_number, 0, 15);
    sprintf(c_str_number, "%lu", proxy->ID);
    const char* execve_kernel_args[] = {c_str_number, NULL};
    const char* execve_kernel_envs[] = {NULL};
    return pec_symbols.kernel_execve(PATH_TO_PROXY, execve_kernel_args, execve_kernel_envs);
}

static int pec_init_symbols(void) {
    pec_symbols.getname = get_callsym_by_name("getname");
    if (pec_symbols.getname == NULL) {
        FATAL("symbol 'getname' not found\n");
        return -1;
    }
    INFO("symbol 'getname' found\n");

    pec_symbols.putname = get_callsym_by_name("putname");
    if (pec_symbols.putname == NULL) {
        FATAL("symbol 'putname' not found\n");
        return -1;
    }
    INFO("symbol 'putname' found\n");

    pec_symbols.kernel_execve = get_callsym_by_name("kernel_execve");
    if (pec_symbols.kernel_execve == NULL) {
        FATAL("symbol 'kernel_execve' not found\n");
        return -1;
    }
    INFO("symbol 'kernel_execve' found\n");

    pec_symbols.syscall_table = get_callsym_by_name("sys_call_table");
    if (pec_symbols.syscall_table == NULL) {
        FATAL("symbol 'syscall_table' not found\n");
        return -1;
    }
    INFO("symbol 'syscall_table' found\n");

    enable_page_rw(pec_symbols.syscall_table);
    pec_symbols.original_execve = pec_symbols.syscall_table[__NR_execve];
    pec_symbols.syscall_table[__NR_execve] = pec_execve;
    disable_page_rw(pec_symbols.syscall_table);
    if (pec_symbols.original_execve == NULL) {
        FATAL("symbol 'execve' not found in syscall_table\n");
        return -1;
    }

    pec_symbols.alloc_file_clone = get_callsym_by_name("alloc_file_clone");
    if (pec_symbols.alloc_file_clone == NULL) {
        FATAL("symbol 'alloc_file_clone' not found in syscall_table\n");
        return -1;
    }

    pec_store_init();
    return 0;
}

static void pec_destroy_symbols(void) {
    enable_page_rw(pec_symbols.syscall_table);
    pec_symbols.syscall_table[__NR_execve] = pec_symbols.original_execve;
    disable_page_rw(pec_symbols.syscall_table);
    memset(&pec_symbols, 0, sizeof(pec_symbols));
}

typedef struct pec_private_data {
    pec_entity_t type;
    service_t* service;
    proxy_t* proxy;
    dummy_file_t* dummy_file;
    void* entity_local_data;
} pec_private_data_t;

typedef struct init_worker_data {
    bool arg_read;
    char* args;
    size_t pos;
    size_t args_len;
}init_worker_data_t;

static int pec_open(struct inode *inode, struct file *file) {
    (void)inode;
    pec_private_data_t* private_data = vmalloc(sizeof(pec_private_data_t));
    if (private_data == NULL){
        return -ENOMEM;
    }
    memset(private_data, 0, sizeof(pec_private_data_t));
    file->private_data = private_data;
    return 0;
}

static ssize_t pec_read (struct file *file, char __user *str, size_t size, loff_t* ppos) {
    pec_private_data_t* private_data = file->private_data;

    struct {
        pec_ring_buffer_t* buffer;
        spinlock_t* buffer_lock;
        wait_queue_head_t* wait;
    } read_data = {NULL, NULL, NULL};

    switch (private_data->type) {
        case UNDEFINED:
        case SERVICE:
            return -EPERM;
        case SERVICE_WORKER: {
            init_worker_data_t *d = private_data->entity_local_data;
            if (d->arg_read) {
                if (d->pos >= d->args_len)
                    return 0;
                if (size > d->args_len - d->pos)
                    size = d->args_len - d->pos;
                copy_to_user(str, d->args, size);
                d->pos += size;
                return size;
            }
            read_data.buffer = &private_data->proxy->stdin_buffer;
            read_data.buffer_lock = &private_data->proxy->stdin_buffer_lock;
            read_data.wait = &private_data->proxy->stdin_wait;
        }
            break;
        case PROXY_PROCESS:
            read_data.buffer = &private_data->proxy->stdout_buffer;
            read_data.buffer_lock = &private_data->proxy->stdout_buffer_lock;
            read_data.wait = &private_data->proxy->stdout_wait;
            break;
    }

    spin_lock(read_data.buffer_lock);
    size_t len = read_data.buffer->payload_len;
    spin_unlock(read_data.buffer_lock);

    if (file->f_flags & O_NONBLOCK) {
        if (len == 0)
            return -EAGAIN;
    } else
        wait_event_interruptible(*read_data.wait, (len > 0));

    spin_lock(read_data.buffer_lock);
    size_t bytes_read = pec_ring_buffer_read(read_data.buffer, (u8*)str, size);
    spin_unlock(read_data.buffer_lock);
    return bytes_read;
}

static ssize_t pec_write (struct file *file, const char __user *str, size_t size, loff_t *ppos) {
    pec_private_data_t* private_data = file->private_data;

    struct {
        pec_ring_buffer_t* buffer;
        spinlock_t* buffer_lock;
        wait_queue_head_t* wait;
    } write_data = {NULL, NULL, NULL};

    switch (private_data->type) {
        case UNDEFINED:
        case SERVICE:
            return -EPERM;
        case SERVICE_WORKER: {
            init_worker_data_t *d = private_data->entity_local_data;
            if (d->arg_read)
                return -EPERM;
            write_data.buffer = &private_data->proxy->stdout_buffer;
            write_data.buffer_lock = &private_data->proxy->stdout_buffer_lock;
            write_data.wait = &private_data->proxy->stdout_wait;
            break;
        }
        case PROXY_PROCESS:
            write_data.buffer = &private_data->proxy->stdin_buffer;
            write_data.buffer_lock = &private_data->proxy->stdin_buffer_lock;
            write_data.wait = &private_data->proxy->stdin_wait;
            break;
    }


    spin_lock(write_data.buffer_lock);
    int ret = pec_ring_buffer_write(write_data.buffer, (const u8*)str, size);
    spin_unlock(write_data.buffer_lock);

    if (!(file->f_flags & O_NONBLOCK)) {
        wake_up(write_data.wait);
    }

    return ret;
}

static unsigned int pec_poll( struct file *file, struct poll_table_struct *poll ) {
    pec_private_data_t* private_data = file->private_data;
    int flag = POLLOUT | POLLWRNORM;
    switch (private_data->type) {
        case UNDEFINED:
            flag = POLLNVAL;
            break;
        case SERVICE:{
            poll_wait(file, &private_data->service->ioctl_wait, poll );
            bool proxy_is_ready = raw_proxy_queue_is_empty(&private_data->service->row_proxy_queue);
            if (proxy_is_ready)
                flag |= (POLLIN | POLLWRNORM);
        }
            break;
        case PROXY_PROCESS: {
            poll_wait(file, &private_data->proxy->stdout_wait, poll);
            poll_wait(file, &private_data->proxy->ioctl_wait, poll);
            spin_lock(&private_data->proxy->stdout_buffer_lock);
            size_t read_ready = private_data->proxy->stdout_buffer.payload_len > 0;
            spin_unlock(&private_data->proxy->stdout_buffer_lock);
            if (read_ready) {
                flag |= (POLLIN | POLLWRNORM);
            }
            if (atomic_read(&private_data->proxy->ret_code_ready)) {
                flag |= POLLIN | POLLWRNORM;
            }
        }
            break;
        case SERVICE_WORKER: {
            poll_wait(file, &private_data->proxy->stdin_wait, poll);
            spin_lock(&private_data->proxy->stdin_buffer_lock);
            size_t read_ready = private_data->proxy->stdin_buffer.payload_len > 0;
            spin_unlock(&private_data->proxy->stdin_buffer_lock);
            if (read_ready) {
                flag |= (POLLIN | POLLWRNORM);
            }
        }
            break;
    }
    return flag;
};

int pec_flush (struct file *file, fl_owner_t id) {
    pec_private_data_t* private_data = file->private_data;
    switch (private_data->type) {
        case UNDEFINED:
            break;
        case PROXY_PROCESS:
            rhashtable_remove_fast(&storage.proxy, &private_data->proxy->head, proxy_params);
            proxy_destroy(private_data->proxy, NULL);
            private_data->proxy = NULL;
            break;
        case SERVICE:
            rhashtable_remove_fast(&storage.services, &private_data->service->head, service_params);
            service_destroy(private_data->service, NULL);
            private_data->service = NULL;
            break;
        case SERVICE_WORKER:
            break;
    }

    vfree(private_data);
    return 0;
}

typedef enum pec_ioctl_call{
    INIT_DUMMY_FILE = 0,
    INIT_SERVICE = 1,
    ASSOCIATE_SERVICE_WITH_DUMMY_FILE = 3,
    INIT_PROXY = 4,
    INIT_SERVICE_WORKER = 5,
    SWITCH_SERVICE_WORKER_READ_MOD = 6
} pec_ioctl_call_t;

ssize_t pec_init_dummy_file (pec_private_data_t* private_data, const char __user* args) {
    if (private_data->type != UNDEFINED)
        return -EPERM;
    struct filename* fname = pec_symbols.getname(args);
    char* fname_str = vzalloc(strlen(fname->name) + 1);
    strcpy(fname_str, fname->name);
    pec_symbols.putname(fname);
    if (pec_storage_create_dummy_file(&storage, fname_str) == NULL)
        return -EEXIST;
    INFO("create dummy file %s", fname_str);
    return 0;
}

ssize_t pec_init_service (pec_private_data_t* private_data) {
    if (private_data->type != UNDEFINED)
        return -EPERM;

    service_t * service = pec_storage_create_service(&storage);
    if (service == NULL)
        return -EAGAIN;

    private_data->type = SERVICE;
    private_data->service = service;
    INFO("create service wuth id %lu", service->ID);
    return 0;
}

ssize_t pec_associate_service_with_dummy_file (pec_private_data_t* private_data, const char* fname) {
    if (private_data->type != SERVICE)
        return -EPERM;

    service_t* service = private_data->service;
    read_lock(&storage.dummy_file_lock);
    struct filename* file_name = pec_symbols.getname(fname);
    INFO("start associate dummy file - '%s' with service - %lu", file_name->name, service->ID);
    dummy_file_t* dummy_file = pec_storage_find_dummy_file_by_fnmae(&storage, file_name->name);
    pec_symbols.putname(file_name);
    if (dummy_file == NULL) {
        INFO("dummy file - '%s' not found", file_name->name);
        read_unlock(&storage.dummy_file_lock);
        return -ENOENT;
    }
    if (dummy_file->service != NULL) {
        read_unlock(&storage.dummy_file_lock);
        return -EBUSY;
    }
    dummy_file->service = service;
    read_unlock(&storage.dummy_file_lock);
    return dummy_file->ID;
}

ssize_t pec_init_proxy (struct file *f, pec_private_data_t* private_data, size_t proxy_id) {
    if (private_data->type != UNDEFINED)
        return -EPERM;

    proxy_t* proxy = pec_storage_find_proxy_by_id(&storage, proxy_id);
    if (proxy == NULL)
        return -EBADF;

    private_data->type = PROXY_PROCESS;
    private_data->service = proxy->service;
    private_data->proxy = proxy;
    raw_proxy_queue_push(&private_data->service->row_proxy_queue, proxy);
    if (!(f->f_flags & O_NONBLOCK)) {
        wake_up(&private_data->service->ioctl_wait);
    }
    return 0;
}

ssize_t pec_init_service_worker(struct file *f, pec_private_data_t* private_data, size_t* dummy_file_id) {
    if (private_data->type != SERVICE)
        return -EPERM;
    if (f->f_flags & O_NONBLOCK) {
        if (raw_proxy_queue_is_empty(&private_data->service->row_proxy_queue))
            return -EAGAIN;
    } else
        wait_event_interruptible(private_data->service->ioctl_wait, (!raw_proxy_queue_is_empty(&private_data->service->row_proxy_queue)));

    proxy_t * proxy = raw_proxy_queue_pop(&private_data->service->row_proxy_queue);
    struct file* new_file = pec_symbols.alloc_file_clone(f, f->f_flags, f->f_op);
    int new_file_fd = get_unused_fd_flags(new_file->f_flags);
    fd_install(new_file_fd, new_file);

    pec_private_data_t* new_private_data = vmalloc(sizeof(pec_private_data_t));
    new_private_data->service = private_data->service;
    new_private_data->proxy = proxy;
    new_private_data->dummy_file = private_data->dummy_file;
    new_private_data->type = SERVICE_WORKER;
    new_file->private_data = new_private_data;

    copy_to_user(dummy_file_id, proxy->dummy_file_ID, sizeof(size_t));

    size_t args_len = 0;
    args_len += strlen(proxy->program_args->file) + 1;
    size_t i;
    for (i = 0; proxy->program_args->arg[i] != NULL; i++)
        args_len += strlen(proxy->program_args->arg[i]) + 1;
    args_len += 1;
    for (i = 0; proxy->program_args->envp[i] != NULL; i++)
        args_len += strlen(proxy->program_args->envp[i]) + 1;
    args_len += 1;

    init_worker_data_t* init_worker_data = vmalloc(sizeof(init_worker_data_t));
    init_worker_data->pos = 0;
    init_worker_data->args = vzalloc(args_len);
    strncpy(init_worker_data->args, proxy->program_args->file, strlen(proxy->program_args->file));
    init_worker_data->pos += strlen(proxy->program_args->file) + 1;
    for (i = 0; proxy->program_args->arg[i] != NULL; i++) {
        strncpy(init_worker_data->args + init_worker_data->pos, proxy->program_args->arg[i], strlen(proxy->program_args->arg[i]));
        init_worker_data->pos += strlen(proxy->program_args->arg[i]) + 1;
    }
    init_worker_data->pos += 1;
    for (i = 0; proxy->program_args->envp[i] != NULL; i++) {
        strncpy(init_worker_data->args + init_worker_data->pos, proxy->program_args->envp[i], strlen(proxy->program_args->envp[i]));
        init_worker_data->pos += strlen(proxy->program_args->envp[i]) + 1;
    }
    init_worker_data->pos = 0;
    init_worker_data->arg_read = true;
    private_data->entity_local_data = init_worker_data;
    return new_file_fd;
}

enum service_worker_read_mod{
    ARGUMENTS,
    DATA
};

ssize_t pec_switch_service_worker_read_mod(pec_private_data_t* private_data, enum service_worker_read_mod mod) {
    if (private_data->type != SERVICE_WORKER)
        return -EPERM;
    if (mod == ARGUMENTS)
        ((init_worker_data_t*)private_data->entity_local_data)->arg_read = true;
    else
        ((init_worker_data_t*)private_data->entity_local_data)->arg_read = false;
    return 0;
}

ssize_t pec_ioctl (struct file *f, unsigned int cmd, unsigned long args) {
    pec_ioctl_call_t call = cmd;
    pec_private_data_t* private_data = f->private_data;
    INFO("ioctl cmd %d", cmd);
    switch (call) {
        case INIT_DUMMY_FILE:
            return pec_init_dummy_file(private_data, (const char *) args);
        case INIT_SERVICE:
            return pec_init_service(private_data);
        case ASSOCIATE_SERVICE_WITH_DUMMY_FILE:
            return pec_associate_service_with_dummy_file(private_data, args);
        case INIT_PROXY:
            return pec_init_proxy(f, private_data, args);
        case INIT_SERVICE_WORKER:
            return pec_init_service_worker(f, private_data, (size_t *) args);
        case SWITCH_SERVICE_WORKER_READ_MOD:
            return pec_switch_service_worker_read_mod(private_data, args);
    }
    return -EPERM;
}

struct file_operations fops = {
        .poll = pec_poll,
        .flush = pec_flush,
        .read = pec_read,
        .write = pec_write,
        .open = pec_open,
        .unlocked_ioctl = pec_ioctl,
};

static struct {
    dev_t dev;
    struct cdev pec_cdev;
    struct class *dev_class;
} device = {.dev = 0};



static int __init pec_init(void) {
    callsym_getter_init();
    if (alloc_chrdev_region(&device.dev, 0, 1, modname) < 0)
        FATAL("cannot allocate major\n");

    cdev_init(&device.pec_cdev, &fops);
    if (cdev_add(&device.pec_cdev, device.dev, 1) < 0) {
        unregister_chrdev_region(device.dev, 1);
        FATAL("cannot add the device to the system\n");
    }

    if ((device.dev_class = class_create(THIS_MODULE, modname)) == NULL) {
        unregister_chrdev_region(device.dev, 1);
        class_destroy(device.dev_class);
        FATAL("cannot create the struct class\n");
    }

    if((device_create(device.dev_class, NULL,device.dev, NULL, modname)) == NULL)
        FATAL("cannot create the PEC device \n\n");

    INFO("device load success\n");
    pec_init_symbols();
    return 0;
}


static void __exit pec_exit(void)
{
    pec_destroy_symbols();
    pec_destroy();
    device_destroy(device.dev_class, device.dev);
    class_destroy(device.dev_class);
    cdev_del(&device.pec_cdev);
    unregister_chrdev_region(device.dev, 1);
    INFO("device unload success\n");
}

module_init(pec_init);
module_exit(pec_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Mamedov Anton");