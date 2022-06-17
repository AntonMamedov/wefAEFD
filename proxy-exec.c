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

#include "logger.h"

#define DEFAULT_BUFFER_SIZE 4096

static struct {

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
    wait_queue_entry_t ioctl_wait;
    spinlock_t stdin_buffer_lock;
    spinlock_t stdout_buffer_lock;
    program_args_t* program_args;
    struct rhash_head head;
};

static proxy_t* new_proxy(size_t ID, service_t *service, program_args_t* args) {
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
}

static void proxy_destroy(proxy_t* dst, void*) {
    destroy_program_args(dst->program_args);
    spin_lock(&dst->stdin_buffer_lock);
    spin_lock(&dst->stdout_buffer_lock);
    pec_ring_buffer_destroy(&dst->stdin_buffer);
    pec_ring_buffer_destroy(&dst->stdout_buffer);
    spin_unlock(&dst->stdout_buffer_lock);
    spin_unlock(&dst->stdin_buffer_lock);
}

typedef struct raw_proxy_queue {
    struct list_head queue_list;
    proxy_t* proxy;
} raw_proxy_queue_t;

static void  raw_proxy_queue_init(raw_proxy_queue_t dst) {
    INIT_LIST_HEAD_RCU(&dst.queue_list);
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
    raw_proxy_queue_init(service->row_proxy_queue);

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
    for (i = 0; str[i] != 0; i++) {
        hash_value = (hash_value + (str[i] - 'a' + 1) * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash_value;
}

static u32 dummy_file_hash(const void *data, u32 len, u32 seed) {
    return string_hash(((dummy_file_t*)data)->fname, len, seed);
}

static int dummy_file_cmp(struct rhashtable_compare_arg *arg,
                   const void *obj) {
    return strcmp((const char*)arg->key, ((dummy_file_t*)obj)->fname);
}

static struct rhashtable_params dummy_file_param = {
        .key_len = 0,
        .key_offset = offsetof(dummy_file_t, fname),
        .head_offset = offsetof(dummy_file_t, head),
        .obj_cmpfn = dummy_file_cmp,
        .obj_hashfn = dummy_file_hash,
        .hashfn = string_hash,
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

    dummy_file_t* old = rhashtable_lookup_get_insert_fast(&dst->dummy_files, &dummy_file->head, dummy_file_param);
    if (old != NULL) {
        dummy_file_destroy(dummy_file, NULL);
        return NULL;
    }

    return dummy_file;
}

static pec_storage_t storage;

typedef struct pec_private_data {
    pec_entity_t type;
    service_t* service;
    proxy_t* proxy;
    dummy_file_t* dummy_file;
} pec_private_data_t;

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
        case SERVICE_WORKER:
            read_data.buffer = &private_data->proxy->stdin_buffer;
            read_data.buffer_lock = &private_data->proxy->stdin_buffer_lock;
            read_data.wait = &private_data->proxy->stdin_wait;
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
        case SERVICE_WORKER:
            write_data.buffer = &private_data->proxy->stdout_buffer;
            write_data.buffer_lock = &private_data->proxy->stdout_buffer_lock;
            write_data.wait = &private_data->proxy->stdout_wait;
            break;
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
            spin_lock(&private_data->proxy->stdout_buffer_lock);
            size_t read_ready = private_data->proxy->stdout_buffer.payload_len > 0;
            spin_unlock(&private_data->proxy->stdout_buffer_lock);
            if (read_ready) {
                flag |= (POLLIN | POLLWRNORM);
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


ssize_t pec_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    if (cmd > 7)
        return -EPERM;

    enum pec_call call = cmd;
    switch (call) {
        case REGISTER_FILE:
            return register_file(file, arg);
        case REGISTER_SERVICE:
            return register_service(file, arg);
        case INIT_SERVICE:
            return init_service(file);
        case INIT_PROXY:
            return init_proxy(file, arg);
    }
}

int pec_execve(struct pt_regs *args) {
    struct filename* fln = pec_meta.getname((const char*)args->di);
    service_node_t * pn = NULL;
    uint64_t service_id = 0;
    enum pec_store_error err = pec_store_get_service_by_file(&store, fln, &pn);
    pec_meta.putname(fln);
    if (err != OK) {
        return pec_meta.original_execve(args);
    }
    service_id = pn->ID;
    uint64_t proxy_id = 0;
    program_args_t* pg = new_program_args((const char*)args->di, (const char* const*) args->si, (const char* const*)args->dx, pec_meta.getname, pec_meta.putname);
    err = pec_store_create_proxy(&store, service_id, pg, &proxy_id);
    if (err != OK) {
        destroy_program_args(pg, pec_meta.putname);
        return -1;
    }
    INFO("a request was made to execute the file %s, an id=%llu was assigned to the proxy process", pg->file, proxy_id);
    char c_str_number[15];
    memset(c_str_number, 0, 15);
    sprintf(c_str_number, "%llu", proxy_id);
    const char* execve_kernel_args[] = {c_str_number, NULL};
    const char* execve_kernel_envs[] = {NULL};
    return pec_meta.kernel_execve(PATH_TO_PROXY, execve_kernel_args, execve_kernel_envs);
}

struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = pec_open,
    .read = pec_read,
    .write = pec_write,
    .poll = pec_poll,
    .flush = pec_flush
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
    struct file *file;

    if ((device.dev_class = class_create(THIS_MODULE, modname)) == NULL) {
        unregister_chrdev_region(device.dev, 1);
        class_destroy(device.dev_class);
        FATAL("cannot create the struct class\n");
    }

    if((device_create(device.dev_class, NULL,device.dev, NULL, modname)) == NULL)
        FATAL("cannot create the PEC device \n\n");
    if (pec_init_symbols() < 0) {
        return 0;
    }
    INFO("device load success\n");
    return 0;
}

static void __exit pec_exit(void)
{
    pec_destroy_symbols();
    device_destroy(device.dev_class, device.dev);
    class_destroy(device.dev_class);
    cdev_del(&device.pec_cdev);
    unregister_chrdev_region(device.dev, 1);
    INFO("device unload success\n");
}


module_init(pec_init);
module_exit(pec_exit);

ssize_t register_file(struct file *file, const char __user*  arg) {
    struct filename* f = pec_meta.getname(arg);
    if (pec_store_register_file(&store, f) == FILE_ALREADY_EXISTS) {
        return -EBUSY;
    }
    return 0;
}

ssize_t init_service(struct file *file) {
    uint64_t service_id = 0;
    service_node_t * sn = NULL;
    enum pec_store_error err = pec_store_create_service(&store, &sn);
    if (err != OK) {
        return -EPERM;
    }
    struct pec_service_data* d = vmalloc(sizeof(struct pec_service_data*));
    file->private_data = d;
    return sn->ID;
}

ssize_t register_service(struct file *file,  const char __user* arg) {
    struct filename* fname = pec_meta.getname(arg);
    uint64_t service_id = ((struct pec_service_data*)file->private_data)->service_node->ID;
    uint64_t file_id = 0;
    enum pec_store_error err = pec_store_associate_service_with_file(&store, service_id, fname, &file_id);
    vfree(fname);
    switch (err) {
        case OK:
            return file_id;
        default:
            break;
    }
    return -EPERM;
}

ssize_t init_proxy(struct file *file,  uint64_t proxy_ID) {
    proxy_node_t* n = NULL;
    pec_store_get_proxy_data(&store, proxy_ID, &n);
    if (n == NULL) {
        return -1;
    }
    struct pec_proxy_data* data = vmalloc(sizeof(struct pec_proxy_data*));
    data->proxy_node = n;
    data->service_node = get_service_node_by_id(&store, n->service_ID);
    file->private_data = data;
    return 0;
}

ssize_t register_service_worker(struct file *file,  uint64_t proxy_ID) {
    proxy_node_t* n = NULL;
    pec_store_get_proxy_data(&store, proxy_ID, &n);
    if (n == NULL) {
        return -1;
    }
    struct pec_proxy_data* data = vmalloc(sizeof(struct pec_proxy_data*));
    data->proxy_node = n;
    data->service_node = get_service_node_by_id(&store, n->service_ID);
    file->private_data = data;
    return 0;
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Mamedov Anton");
