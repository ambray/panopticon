#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include "defs.h"

/* Forward Declarations */
static int  panop_file_open(struct file* f, const struct cred* cred);

/* Globals */
static struct security_hook_list panop_hooks[] = {
  { .head = NULL, .hook = { .file_open = panop_file_open}, },
};

unsigned long get_security_hooks(struct security_hook_list** list)
{
  *list = panop_hooks;
  return ARRAY_SIZE(panop_hooks);
}

static int panop_file_open(struct file* f, const struct cred* cred)
{

  dbg_print("File Open: %s", f->f_path.dentry->d_iname);

  return 0;
}
