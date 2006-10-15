#include <linux/netfilter_ipv4/ip_tables.h>
#include "ipt_pknock.h"


static int match(const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const void *matchinfo,
		int offset,
		int *hotdrop) 
{
	return 1;
}


static int checkentry(const char *tablename,
		const struct ipt_ip *ip,
		void *matchinfo,
		unsigned int matchinfosize,
		unsigned int hook_mask) 
{
	return 1;
}


static void destroy(void *matchinfo, unsigned int matchinfosize) 
{

}


static struct ipt_match ipt_pknock_match = {
	.name 		= "pknock",
	.match 		= match,
	.checkentry 	= checkentry,
	.destroy	= destroy,
	.me 		= THIS_MODULE
};


static int __init ipt_pknock_init(void) 
{
	return ipt_register_match(&ipt_pknock_match);
}


static void __exit ipt_pknock_fini(void)
{
	ipt_unregister_match(&ipt_pknock_match);
}


module_init(ipt_pknock_init);
module_exit(ipt_pknock_fini);
