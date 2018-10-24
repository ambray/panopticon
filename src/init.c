#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include "defs.h"

MODULE_LICENSE("GPL");

#define HOOK_HEADS_NAME   "security_hook_heads"

static void* hook_loc = NULL;


static int __init panop_init(void)
{
  if(0 == (hook_loc = (void*)kallsyms_lookup_name(HOOK_HEADS_NAME))) {
    dbg_print("Failed to find %s!", HOOK_HEADS_NAME);
    return -1;
  }

  dbg_print("Hook location: 0x%lx", (unsigned long)hook_loc);
  return 0;
}

static void __exit panop_exit(void)
{
  dbg_print("-> Exiting module");
}

module_init(panop_init);
module_exit(panop_exit);
