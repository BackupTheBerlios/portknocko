#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>	/* standard well-defined ip protocols */
#include <linux/netlink.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Purcell");
MODULE_DESCRIPTION("Kernel Korner's working versinon of netlink sockets");

// Note: Debug is not implemented
static int debug = 0;

module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug information (default 0)");

static struct sock *nl_sk = NULL;

static void nl_data_ready (struct sock *sk, int len)
{
    wake_up_interruptible(sk->sk_sleep);
}

static int netlink_test(void)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    int err;
    u32 pid;
    
    nl_sk = netlink_kernel_create(NETLINK_TEST, 1, nl_data_ready, THIS_MODULE);    

    if (!nl_sk) {
        printk(KERN_INFO "ERROR iniitializing Netlink Socket\n");
        return -ENOMEM;
    }    
    
    
    skb = skb_recv_datagram(nl_sk, 0, 0, &err);
    
    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "%s: received netlink message payload: %s\n", __FUNCTION__, NLMSG_DATA(nlh));
    
    pid = nlh->nlmsg_pid;
    NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).dst_pid = pid;
    NETLINK_CB(skb).dst_group = 0;
    strcpy(NLMSG_DATA(nlh), "Hola Mundo desde kernel!");
    netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);

    sock_release(nl_sk->sk_socket);
    return 0;
}

static int __init my_module_init(void)
{
    printk(KERN_INFO "Initializing Netlink Socket");
    return netlink_test();
}

static void __exit my_module_exit(void)
{
    printk(KERN_INFO "Goodbye");
}

module_init(my_module_init);
module_exit(my_module_exit);
