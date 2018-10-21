#pragma once

#include <linux/module.h>

#if defined(DBG)
#define dbg_print(x, ...) printk(KERN_ALERT "[panop]%s:%d> " #x\
                                 "\n", __FILE__, __LINE__,##__VA_ARGS__)
#else
#define dbg_print(x, ...) ""
#endif
