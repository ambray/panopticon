#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");


static int __init panop_init(void)
{
  return 0;
}

static void __exit panop_exit(void)
{
  
}

module_init(panop_init);
module_exit(panop_exit);
