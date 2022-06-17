#ifndef PROXY_EXEC_LINUX_KERNEL_MODULE_LOGGER_H
#define PROXY_EXEC_LINUX_KERNEL_MODULE_LOGGER_H



// The name of this module (several options)
//#define MYNAME THIS_MODULE->name
#define MYNAME KBUILD_MODNAME
static const char modname[]=MYNAME;

// do we want debug information ?!?
//#define DO_DEBUG
// TODO - the macros here could (and should?!?) be turned into inline functions...

#ifdef DO_DEBUG
#define DEBUG(fmt,args...) printk(KERN_DEBUG "DEBUG: %s %s %s %d: " fmt "\n",modname,__BASE_FILE__,__FUNCTION__,__LINE__,## args)
#else // DO_DEBUG
#define DEBUG(fmt,args...)
#endif // DO_DEBUG

// warnings are always show as KERN_WARNING; WARNING does not do a BUG() (guaranteed)
#define WARNING(fmt,args...) printk(KERN_WARNING "WARNING: %s %s %s %d: " fmt "\n",modname,__BASE_FILE__,__FUNCTION__,__LINE__,## args);

// errors are always shown as KERN_ERR; ERROR does not do a BUG()
#define ERROR(fmt,args...) printk(KERN_ERR "ERROR: %s %s %s %d: " fmt "\n",modname,__BASE_FILE__,__FUNCTION__,__LINE__,## args);

// fatals are always shown as KERN_ERR; FATAL also does a BUG()
#define FATAL(fmt,args...) printk(KERN_ERR "FATAL: %s %s %s %d: " fmt "\n",modname,__BASE_FILE__,__FUNCTION__,__LINE__,## args);

// prints are always show as KERN_INFO
#define INFO(fmt,args...) printk(KERN_INFO "INFO: %s %s %s %d: " fmt "\n",modname,__BASE_FILE__,__FUNCTION__,__LINE__,## args);


#endif //PROXY_EXEC_LINUX_KERNEL_MODULE_LOGGER_H
