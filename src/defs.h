#pragma once

#include <linux/module.h>

#if defined(DBG)
#define dbg_print(x, ...) printk(KERN_ALERT "[panop]%s:%d> " #x\
                                 "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define dbg_print(x, ...) ""
#endif


#define FILE_STATIC_SIZE 64
#define JSON_BEGIN_PREFIX   "{\"type\":\""
#define JSON_END_PREFIX     "\","
#define JSON_SUFFIX         "}"
#define JSON_INT_PAIR       "\"%s\":%u"
#define JSON_STR_PAIR       "\"%s\":\"%s\""
#define JSON_UL_PAIR        "\"%s\":%lu"
#define STATIC_SIZE  64
#define FILE_OPEN    "file_open"
#define UID_KEY      "uid"
#define GID_KEY      "gid"
#define PATH_KEY     "path"
#define MODE_KEY     "mode"
#define FLAGS_KEY    "flags"
#define INODE_KEY    "inode"
