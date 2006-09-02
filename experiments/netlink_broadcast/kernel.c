#include <linux/module.h>
#include <linux/connector.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luis A. Floreani");
MODULE_DESCRIPTION("Generic userspace <-> kernelspace connector.");

#define GROUP 1

static struct cb_id cn_test_id = { 0x123, 0x345 };
static int cn_test_timer_counter;

int netlink_test(void) {
    struct cn_msg *m;
    char data[64];
    
    m = kmalloc(sizeof(*m) + sizeof(data), GFP_ATOMIC);
    if (m) {
        memset(m, 0, sizeof(*m) + sizeof(data));
        
        memcpy(&m->id, &cn_test_id, sizeof(m->id));
        m->seq = cn_test_timer_counter;
        m->len = sizeof(data);
        m->len = scnprintf(data, sizeof(data), "counter = %u", cn_test_timer_counter) + 1;
        
        cn_test_timer_counter++;
        
        memcpy(m + 1, data, m->len);
        
        cn_netlink_send(m, GROUP, gfp_any());
        
	kfree(m);
    }
    
    return 0;	
    
} 

static int __init my_module_init(void) {
	return netlink_test();
}

static void __exit my_module_exit(void) {
    
}

module_init(my_module_init);
module_exit(my_module_exit);
