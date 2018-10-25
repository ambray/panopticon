#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/lsm_hooks.h>
#include <linux/rculist.h>
#include "defs.h"

MODULE_LICENSE("GPL");

#define HOOK_HEADS_NAME   "security_hook_heads"
#define ADD_HOOKS_NAME    "security_add_hooks"

/* Forward Declarations */
static int panop_file_open(struct file* f, const struct cred* cred);

/* Globals */
static void* hook_loc = NULL;
static struct security_hook_list panop_hooks[] = {
  { .head = NULL, .hook = { .file_open = panop_file_open}, },
};


static unsigned long unprotect(void)
{
  unsigned long cr0;
  dbg_print("-> Disabling write protection so we don't asplode");
  preempt_disable();
  smp_mb();
  cr0 = read_cr0();

  write_cr0(cr0 & ~X86_CR0_WP); // TODO: multi-arch
  return cr0;
}

static void reprotect(unsigned long old_cr0)
{
  write_cr0(old_cr0);
  smp_mb();
  preempt_enable();
  dbg_print("-> Write protection restored");
}

static void add_hooks_to_list(struct security_hook_list* hooks, int count)
{
  int i = 0;
  unsigned long cr0 = 0;

  cr0 = unprotect();

  for(; i < count; i++)
    list_add_rcu(&hooks[i].list, hooks[i].head);

  reprotect(cr0);
}

static void rem_hooks_from_list(struct security_hook_list* hooks, int count)
{
  int i = 0;
  unsigned long cr0 = 0;

  cr0 = unprotect();

  for (; i < count; i++)
    list_del_rcu(&hooks[i].list);

  reprotect(cr0);
}

static void set_hooks(void)
{
  struct security_hook_heads* hook_heads = NULL;

  if(!hook_loc)
    return;

  hook_heads = (struct security_hook_heads*)hook_loc;

  /* Initialize the entries */
  panop_hooks[0].head = &hook_heads->file_open;


  add_hooks_to_list(panop_hooks, ARRAY_SIZE(panop_hooks));
}

static void clear_hooks(void)
{
  if(!hook_loc)
    return;

  rem_hooks_from_list(panop_hooks, ARRAY_SIZE(panop_hooks));
}

static int __init panop_init(void)
{
  if(0 == (hook_loc = (void*)kallsyms_lookup_name(HOOK_HEADS_NAME))) {
    dbg_print("Failed to find %s!", HOOK_HEADS_NAME);
    return -1;
  }

  dbg_print("Hook location: 0x%lx", (unsigned long)hook_loc);
  set_hooks();
  dbg_print("hooks set!");
  return 0;
}

static void __exit panop_exit(void)
{
  if(hook_loc)
    clear_hooks();

  dbg_print("-> Exiting module");
}

static int panop_file_open(struct file* f, const struct cred* cred)
{

  dbg_print("File Open event");

  return 0;
}

module_init(panop_init);
module_exit(panop_exit);
