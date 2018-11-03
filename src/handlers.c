#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include "defs.h"

/* externs */
extern void panop_send(const void* message, unsigned long size);

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

/**
 * Helper method to extract a full path from a given dentry.
 */
static int get_path_from_dentry(struct dentry* d, char** fp, char** buf,
                                unsigned int* s)
{
  char* p = NULL;
  char* rv = NULL;
  unsigned int size = 256;
  int res = 0;
  do {
    if(NULL == (p = kmalloc(size, GFP_KERNEL))) {
      dbg_print("Allocation for size %u failed!", size);
      res = -1;
      goto cleanup;
    }

    if(ERR_PTR(-ENAMETOOLONG) == (rv = dentry_path_raw(d, p, size))) {
      kfree(p);
      size *= 2;
    }

  } while(rv == ERR_PTR(-ENAMETOOLONG));

  *buf = rv;
  *fp = p;

cleanup:
  if(0 != res && NULL != p)
    kfree(p);

  return res;
}

static int marshal_file(const char* type, char** buf, unsigned int* outsize,
                        struct file* f, unsigned int uid, unsigned int gid)
{
  int   res = 0;
  char* path_buf = NULL;
  char* path_scratch = NULL;
  char* p = NULL;
  unsigned int size = strlen(type) + STATIC_SIZE + FILE_STATIC_SIZE
    + sizeof(JSON_UL_PAIR);
  unsigned int offset = 0;
  unsigned int psize = 0;
  int          tmp = 0;

  if(0 != (res = get_path_from_dentry(f->f_path.dentry, &path_scratch,
                                      &path_buf, &psize))) {
    path_scratch = NULL;
    path_buf = f->f_path.dentry->d_iname;
  }

  size += strlen(path_buf);
  if(NULL == (p = kmalloc(size, GFP_KERNEL))) {
    res = -1;
    goto cleanup;
  }

  strcpy(p, JSON_BEGIN_PREFIX);
  offset += sizeof(JSON_BEGIN_PREFIX) - 1;
  strcpy(p + offset, type);
  offset += strlen(type);
  strcpy(p + offset, JSON_END_PREFIX);
  offset += sizeof(JSON_END_PREFIX) - 1;

  tmp = snprintf(p + offset, size - offset, JSON_INT_PAIR, UID_KEY, uid);
  offset += tmp;
  *(p + offset) = ',';
  offset++;
  tmp = snprintf(p + offset, size - offset, JSON_INT_PAIR, GID_KEY, gid);
  offset += tmp;
  *(p + offset) = ',';
  offset++;
  tmp = snprintf(p + offset, size - offset, JSON_UL_PAIR, INODE_KEY,
                 f->f_inode->i_ino);
  offset += tmp;
  *(p + offset) = ',';
  offset++;
  tmp = snprintf(p + offset, size - offset, JSON_STR_PAIR, PATH_KEY, path_buf);
  offset += tmp;
  strcpy(p + offset, JSON_SUFFIX);
  offset += sizeof(JSON_SUFFIX);

  *buf = p;
  *outsize = offset;

cleanup:
  if(path_scratch)
    kfree(path_scratch);

  return res;
}

static int panop_file_open(struct file* f, const struct cred* cred)
{
  char* p = NULL;
  unsigned int size = 0;

  if(0 != marshal_file(FILE_OPEN, &p, &size, f, cred->uid.val, cred->gid.val)) {
    dbg_print("Failed to marshal file!");
    goto cleanup;
  }

  panop_send(p, size);
cleanup:
  if(p)
    kfree(p);

  return 0;
}
