#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/lsm_hooks.h>
#include <linux/rculist.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "defs.h"

MODULE_LICENSE("GPL");

#define HOOK_HEADS_NAME     "security_hook_heads"
#define NETLINK_PANOPTICON  30

/* Forward Declarations */
static int  panop_file_open(struct file* f, const struct cred* cred);
static void panop_nl_recv(struct sk_buff* skb);

/* Globals */
static struct sock* panop_sk = NULL;
static void* hook_loc = NULL;
static struct security_hook_list panop_hooks[] = {
  { .head = NULL, .hook = { .file_open = panop_file_open}, },
};
static struct netlink_kernel_cfg panop_nl_cfg = {
  .input = panop_nl_recv,
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


static int init_netlink(struct sock** s)
{
  dbg_print("About to construct netlink socket...");

  if(NULL == (*s = netlink_kernel_create(&init_net, NETLINK_PANOPTICON,
                                         &panop_nl_cfg))) {
    dbg_print("[x] Netlink socket creation failed!");
    return -10;
  }


  return 0;
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
  int res = 0;

  if(0 == (hook_loc = (void*)kallsyms_lookup_name(HOOK_HEADS_NAME))) {
    dbg_print("Failed to find %s!", HOOK_HEADS_NAME);
    return -1;
  }

  if (0 != (res = init_netlink(&panop_sk))) {
    dbg_print("Netlink creation failed");
    goto done;
  }

  dbg_print("Hook location: 0x%lx", (unsigned long)hook_loc);
  set_hooks();
  dbg_print("hooks set!");
done:
  return res;
}

static void __exit panop_exit(void)
{
  if(hook_loc)
    clear_hooks();
  if(panop_sk)
    netlink_kernel_release(panop_sk);

  dbg_print("-> Exiting module");
}

static int panop_file_open(struct file* f, const struct cred* cred)
{

  dbg_print("File Open: %s", f->f_path.dentry->d_iname);

  return 0;
}

static void panop_nl_recv(struct sk_buff* skb)
{
}

module_init(panop_init);
module_exit(panop_exit);
