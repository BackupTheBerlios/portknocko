/*
 * Kernel module to implement port knocking matching support.
 * 
 * (C) 2006 J. Federico Hernandez <fede.hernandez@gmail.com>
 *
 * $Id: ipt_pknock.c,v 1.29 2006/06/02 21:04:03 brugge Exp $
 *
 * This program is released under the terms of GNU GPL.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>	/* standard well-defined ip protocols */
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>

#include <linux/netfilter_ipv4/ip_tables.h>
//#include <linux/netfilter_ipv4/ipt_pknock.h>
#include "ipt_pknock.h"

MODULE_AUTHOR("J. Federico Hernandez");
MODULE_DESCRIPTION("iptables/netfilter's port knocking match module");
MODULE_LICENSE("GPL");

#define EXPIRATION_TIME 50000 /* in msecs */

static LIST_HEAD(rule_list);
static DEFINE_SPINLOCK(rule_list_lock);
static struct proc_dir_entry *proc_net_ipt_pknock = NULL;

#if DEBUG
/**
 * print_ip_packet()
 *
 * @param struct iphdr *iph
 */
static inline void print_ip_packet(struct iphdr *iph) {
	printk(KERN_INFO MOD "\nIP packet:\n"
		"VER=%d | IHL=%d | TOS=0x%02X | LEN=%d\n"
		"ID=%u | Flags | FRAG_OFF=%d\n"
		"TTL=%x | PROTO=%d | CHK=%d\n"
		"SRC=%u.%u.%u.%u\n"
		"DST=%u.%u.%u.%u\n", 
		iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len),
		ntohs(iph->id), iph->frag_off,
		iph->ttl, iph->protocol, ntohl(iph->check),
		NIPQUAD(iph->saddr), 
		NIPQUAD(iph->daddr));
}

/**
 * print_options()
 *
 * @param struct ipt_pknock_info *info
 */
static inline void print_options(struct ipt_pknock_info *info) {
	int i;

	printk(KERN_INFO MOD "pknock options from kernel:\n"
		"count_ports: %d\ntime: %ld\noption: %d\n", 
		info->count_ports, info->max_time, info->option);
	
	for (i=0; i<info->count_ports; i++)
		printk(KERN_INFO MOD "port[%d]: %d\n", i, info->port[i]);
}

/**
 * print_list_peer()
 *
 * @param struct ipt_pknock_info *info
 */
static inline void print_list_peer(struct ipt_pknock_rule *rule) {
	struct list_head *pos = NULL;
	struct peer_status *peer = NULL;
	u_int32_t ip;

	if (list_empty(&rule->peer_status_head)) return;
	
	printk(KERN_INFO MOD "(*) %s list peer matching status:\n", rule->rule_name);
	
	list_for_each(pos, &rule->peer_status_head) {
		peer = list_entry(pos, struct peer_status, head);
		ip = htonl(peer->ip);
		printk(KERN_INFO MOD "(*) peer: %u.%u.%u.%u - tstamp: %ld\n", 
					NIPQUAD(ip), peer->timestamp);
	}
}
#endif

/**
 * status_itoa()
 *
 * This function converts the status from integer to string.
 *
 * @param enum status
 */
static inline const char *status_itoa(enum status status) {
	switch (status) {
	case ST_INIT: return "INIT";
	case ST_MATCHING: return "MATCHING";
	case ST_ALLOWED: return "ALLOWED";
	}
	return "UNKNOWN";
}

#if 0
static int read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = 0;
	off_t begin = 0;
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)data;

	len += sprintf(page, "(proc) rule_p addr: %s\n", info->rule_name);
	*eof = 1;

	if (off >= len + begin)
		return 0;
	
 	*start = page + (off - begin);
	return ((count < begin + len - off) ? count : begin + len - off);
}

#else

/**
 * read_proc()
 *
 * This function produces the peer matching status data when the file is read.
 */
static int read_proc(char *buf, char **start, off_t offset, int count, int *eof, void *data) {
	int limit = count, len = 0;
	off_t pos = 0, begin = 0;
	u_int32_t ip;
	const char *status = NULL, *proto = NULL;
	struct list_head *p = NULL;
	struct ipt_pknock_rule *rule = NULL;
	struct peer_status *peer = NULL;
	unsigned long expiration_time = 0, max_time = 0;

	*eof=0;
	
	spin_lock_bh(&rule_list_lock);

	rule = (struct ipt_pknock_rule *)data;

	if (list_empty(&rule->peer_status_head)) {
		spin_unlock_bh(&rule_list_lock);
		return 0;
	}
	max_time = rule->max_time;

	list_for_each(p, &rule->peer_status_head) {
		peer = list_entry(p, struct peer_status, head);
		
		status = status_itoa(peer->status);
		
		proto = (peer->proto == IPPROTO_TCP) ? "TCP" : "UDP";
		ip = htonl(peer->ip);
		
/*!*/// 	usar time_before() o alguno de sus derivados.
		expiration_time = ((jiffies/HZ) < (peer->timestamp + max_time)) ?
				((peer->timestamp+max_time)-(jiffies/HZ)) : 0;
/*!*/			
		len += snprintf(buf+len, limit-len, "src=%u.%u.%u.%u ", NIPQUAD(ip));
		len += snprintf(buf+len, limit-len, "proto=%s ", proto);
		len += snprintf(buf+len, limit-len, "status=%s ", status);
		len += snprintf(buf+len, limit-len, "expiration_time=%ld ", 
				expiration_time);
/*		len += snprintf(buf+len, limit-len, "next_port=%d ", 
				info->port[peer->id_port_knocked-1]); */
		len += snprintf(buf+len, limit-len, "next_port_id=%d ",
				peer->id_port_knocked-1);
		len += snprintf(buf+len, limit-len, "\n");
		
		limit -= len;
		
		pos = begin + len;
		if(pos < offset) { len = 0; begin = pos; }
		if(pos > offset + count) { len = 0; break; }
	}
	*start = buf + (offset - begin);
	len -= (offset - begin);
	if(len > count) len = count;
	*eof=1;

	spin_unlock_bh(&rule_list_lock);
	return len;
}

#endif

/**
 * peer_status_gc()
 *
 * Garbage collector. It removes the old entries after that the timer has expired.
 *
 * @param unsigned long r
 */
static void peer_status_gc(unsigned long r) {
	struct ipt_pknock_rule *rule = (struct ipt_pknock_rule *)r;
	struct peer_status *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;

	if(timer_pending(&rule->timer) == 0) {
		if (list_empty(&rule->peer_status_head)) return;

		list_for_each_safe(pos, n, &rule->peer_status_head) {
			peer = list_entry(pos, struct peer_status, head);

			if (peer->status == ST_ALLOWED || peer->status == ST_MATCHING) {
#if DEBUG
				printk(KERN_INFO MOD "(X) peer: %u.%u.%u.%u - DESTROYED\n",
					NIPQUAD(peer->ip));
#endif		
				list_del(pos);
				kfree(peer);
			}
		}
	}
}

/**
 * search_rule()
 *
 * Si la regla existe en la lista, devuelve un puntero a la regla.
 *
 * @param struct ipt_pknock *info
 * @return struct ipt_pknock_rule *
 */
static inline struct ipt_pknock_rule * search_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;

	if (!list_empty(&rule_list)) {
		list_for_each_safe(pos, n, &rule_list) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);
			
			if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) == 0)
				return rule;
		}		
	}
	return NULL;
}

/**
 * add_rule()
 * 
 * It adds a rule to list only if it doesn't exist.
 *
 * @param struct ipt_pknock_info *info
 * @return int: 1 success, 0 otherwise
 */
static int add_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL;

	if (!list_empty(&rule_list)) {
		list_for_each(pos, &rule_list) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);
			/* If the rule exists. */
			if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) == 0) {
				rule->ref_count++;
#if DEBUG
				printk(KERN_DEBUG MOD "(E) rule found: %s - ref_count: %d\n", 
					rule->rule_name, rule->ref_count);
#endif				
				return 1;
			}
		}
	}
	/* If it doesn't exist. */
	if ((rule = (struct ipt_pknock_rule *)kmalloc(sizeof (*rule), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in add_rule() function.\n");
		return 0;
	}

	INIT_LIST_HEAD(&rule->head);
	strncpy(rule->rule_name, info->rule_name, info->rule_name_len);
	rule->ref_count	= 1;
	rule->max_time 	= info->max_time;
//	init_timer(&rule->timer);
//	rule->timer.expires 	= 0;
//	rule->timer.data	= (unsigned long)rule;
//	rule->timer.function 	= peer_status_gc;
//	add_timer(&rule->timer);
	INIT_LIST_HEAD(&rule->peer_status_head);
	
	if (!(rule->status_proc = create_proc_read_entry(info->rule_name, 0, 
	proc_net_ipt_pknock, read_proc, rule))) {
		printk(KERN_ERR MOD "create_proc_entry() error in add_rule() function.\n");
		if (rule) kfree(rule);
		return 0;
	}

	list_add_tail(&rule->head, &rule_list);
#if DEBUG
	printk(KERN_INFO MOD "(A) rule_name: %s - created.\n", rule->rule_name);
#endif	
	return 1;
}


/**
 * remove_rule()
 * 
 * It removes a rule only if it exists.
 *
 * @param struct ipt_pknock_info *info
 */
static void remove_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;
	struct peer_status *peer = NULL;
	
	if (list_empty(&rule_list)) return;

	list_for_each(pos, &rule_list) {
		rule = list_entry(pos, struct ipt_pknock_rule, head);
		/* If the rule exists. */
		if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) == 0) {
			rule->ref_count--;
#if DEBUG
			printk(KERN_DEBUG MOD "(E) rule found: %s - ref_count: %d\n", 
				rule->rule_name, rule->ref_count);
#endif	
			break;
		}
#if DEBUG
		printk(KERN_INFO MOD "(N) rule not found: %s.\n", info->rule_name);
#endif
	}

	if (rule != NULL && rule->ref_count == 0) {
		/* If it had added peers matching status. */
		if (!list_empty(&rule->peer_status_head)) {
			list_for_each_safe(pos, n, &rule->peer_status_head) {
				peer = list_entry(pos, struct peer_status, head);
				if (peer != NULL) {
#if DEBUG
					printk(KERN_INFO MOD "(D) peer deleted: %u.%u.%u.%u\n", 
						NIPQUAD(peer->ip));
#endif					
					list_del(pos);
					kfree(peer);
				}
			}
		}
		
		if (rule->status_proc) remove_proc_entry(info->rule_name, proc_net_ipt_pknock);
#if DEBUG
		printk(KERN_INFO MOD "(D) rule deleted: %s.\n", rule->rule_name);
#endif
//		if (timer_pending(&rule->timer))
//		del_timer(&rule->timer);
				
		list_del(&rule->head);
		kfree(rule);
	}
}

/**
 * update_rule_timer()
 *
 * It updates the rule timer to execute garbage collector.
 *
 * @param struct ipt_pknock_rule *rule
 */
static inline void update_rule_timer(struct ipt_pknock_rule *rule) {
	rule->timer.expires = jiffies + msecs_to_jiffies(EXPIRATION_TIME);
	add_timer(&rule->timer);
}

/**
 * get_peer_status()
 *
 * If peer status exist in the list it returns peer status, if not it returns NULL.
 *
 * @param ipt_pknock_rule *rule
 * @param u_int32_t ip
 * @return struct_conn_status * or NULL
 */
static inline struct peer_status * get_peer_status(struct ipt_pknock_rule *rule, 
									u_int32_t ip) {
	struct peer_status *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;
	
	if (list_empty(&rule->peer_status_head)) return NULL;

	ip = ntohl(ip);
	list_for_each_safe(pos, n, &rule->peer_status_head) {
		peer = list_entry(pos, struct peer_status, head);
		if (peer->ip == ip) return peer;
	}
	return NULL;
}

/**
 * new_peer_status()
 * 
 * It creates a new peer matching status.
 *
 * @param struct ipt_pknock_rule *rule
 * @param u_int32_t ip
 * @param u_int8_t proto
 * @return struct peer_status * or NULL
 */
static inline struct peer_status * new_peer_status(u_int32_t ip, u_int8_t proto) {
	struct peer_status *peer = NULL;

	if ((peer = (struct peer_status *)kmalloc(sizeof (*peer), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in new_peer_status() function.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&peer->head);
	peer->ip 	= ntohl(ip);
	peer->proto 	= proto;
	peer->status 	= ST_INIT;
	peer->timestamp = jiffies/HZ;
	peer->id_port_knocked = 0;

	return peer;
}

/**
 * add_peer_status()
 * 
 * It adds a new peer matching status to the list.
 *
 * @param struct peer_status *peer
 * @param struct ipt_pknock_rule *rule
 */
static inline void add_peer_status(struct peer_status *peer, 
						struct ipt_pknock_rule *rule) {
	list_add_tail(&peer->head, &rule->peer_status_head);
}

/**
 * remove_peer_status()
 *
 * It removes a peer matching status.
 *
 * @param struct peer_status *peer
 */
static inline void remove_peer_status(struct peer_status *peer) {
	list_del(&peer->head);
	if (peer) kfree(peer);
}

/**
 * is_1st_port_match()
 *
 * If packet port (that enters) is equal to the first port saved in buffer, 
 * it returns 1, if not, it returns 0.
 *
 * @param struct ipt_pknock_info *info
 * @param u_int16_t port
 * @return int: 1 port matched, 0 port didn't match
 */
static inline int is_1st_port_match(struct ipt_pknock_info *info, u_int16_t port) {
	return (info->port[0] == port) ? 1 : 0;
}

/**
 * set_peer_status()
 *
 * It sets the peer matching status after that the 1st port has matched.
 *
 * @param struct peer_status *peer
 */
static inline void set_peer_status(struct peer_status *peer) {
	peer->timestamp = jiffies/HZ;
	peer->status = ST_MATCHING;
	peer->id_port_knocked = 1;
}

/**
 * update_peer_status()
 *
 * It updates the peer matching status.
 *
 * @param struct peer_status *peer
 * @param struct ipt_pknock_info *info
 * @param u_int16_t port
 * @return int
 */
static int update_peer_status(struct peer_status *peer, 
					struct ipt_pknock_info *info, 
					u_int16_t port) {
	unsigned long time;
	const char *status = NULL;
	/* 
	 * Verifies the id port that it should knock. 
	 */
	if (info->option & IPT_PKNOCK_SETIP) {
		if (info->port[peer->id_port_knocked-1] != port) {
#if DEBUG
			printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - DIDN'T MATCH.\n", NIPQUAD(peer->ip));
#endif
			return 0;
		}
		peer->id_port_knocked++;
		
		if (peer->id_port_knocked-1 == info->count_ports) {
			peer->status = ST_ALLOWED;
			status = "ALLOWED";
		}
	}
	/* 
	 * Controls the max matching time between ports.
	 */
	if (info->option & IPT_PKNOCK_TIME) {
		time = jiffies/HZ;
		
		if (time > (peer->timestamp + info->max_time)) {
#if DEBUG
			printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - TIME EXCEEDED.\n", NIPQUAD(peer->ip));
			printk(KERN_INFO MOD "(X) peer: %u.%u.%u.%u - DESTROYED.\n", NIPQUAD(peer->ip));
			printk(KERN_INFO MOD "max_time: %ld - time: %ld\n", 
				peer->timestamp + info->max_time, time);
#endif
			remove_peer_status(peer);
			return 1;
		}
		peer->timestamp = time;		
	}
#if DEBUG
	printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - %s.\n", 
		NIPQUAD(peer->ip), (status==NULL) ? "MATCHING" : status);
#endif
	return 1;
}

/**
 * check_peer_status()
 *
 * It checks the peer matching status.
 *
 * @param struct peer_status *peer
 * @return int: 1 allow, 0 otherwise
 */
static inline int check_peer_status(struct peer_status *peer) {
	return (peer->status == ST_ALLOWED) ? 1 : 0;
}

#if 0 
/*!*/ //_SOLO_ para versiones del kernel _SUPERIORES_ a 2.6.12
static int match(const struct sk_buff *skb,
	      const struct net_device *in,
	      const struct net_device *out,
	      const void *matchinfo,
	      int offset,
	      unsigned int protoff,
	      int *hotdrop) 
#endif
/*!*/ //_SOLO_ para versiones del kernel _HASTA_ la 2.6.12
static int match(const struct sk_buff *skb,
	      const struct net_device *in,
	      const struct net_device *out,
	      const void *matchinfo,
	      int offset,
	      int *hotdrop) 
{
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)matchinfo;
	struct ipt_pknock_rule *rule = NULL;
	struct peer_status *peer = NULL;
	struct iphdr *iph = skb->nh.iph;
	int ihl = iph->ihl * 4;
	struct tcphdr *tcph = (void *)iph + ihl;
	struct udphdr *udph = (void *)iph + ihl;
	u_int16_t port = 0;
	u_int8_t proto = 0;
	int ret=0;

	switch ((proto = iph->protocol)) {
	case IPPROTO_TCP:
		port = ntohs(tcph->dest); break;
	
	case IPPROTO_UDP:
		port = ntohs(udph->dest); break;
	
	default:
		printk(KERN_INFO MOD "IP payload protocol is neither tcp nor udp.\n");
		return 0;
	}

	spin_lock_bh(&rule_list_lock);
	/* 
	 * Searches a rule from the list depending on info structure options.
	 */
	if ((rule = search_rule(info)) == NULL) {
		printk(KERN_INFO MOD "The rule %s doesn't exist.\n", info->rule_name);
		return 0;
	}
	/*
	 * Updates the rule timer to execute the garbage collector.
	 */
//	update_rule_timer(rule);
	/* 
	 * Gives the peer matching status added to rule depending on ip source.
	 */
	peer = get_peer_status(rule, iph->saddr);
	/*
	 * Sets, adds, removes or checks the peer matching status.
	 */
	if (info->option & IPT_PKNOCK_SETIP) {
		if (peer == NULL && is_1st_port_match(info, port)) {
			peer = new_peer_status(iph->saddr, proto);
			add_peer_status(peer, rule);
			set_peer_status(peer);
			ret = update_peer_status(peer, info, port);
			
			spin_unlock_bh(&rule_list_lock);
			return ret;
		}
		if (peer != NULL) {
			ret = update_peer_status(peer, info, port);
			
			spin_unlock_bh(&rule_list_lock);
			return ret;
		}
	} else if (info->option & IPT_PKNOCK_CHKIP) {
		if (peer != NULL) {
			ret = check_peer_status(peer);
			
			spin_unlock_bh(&rule_list_lock);
			return ret;
		}
	}
	/*
	 * Default: it doesn't match. 
	 */
	spin_unlock_bh(&rule_list_lock);
	return 0;
}
#if 0 
/*!*/ //_SOLO_ para versiones del kernel superiores a 2.6.12
static int checkentry(const char *tablename,
			const void *ip,
			void *matchinfo,
			unsigned int matchinfosize,
			unsigned int hook_mask) 
#endif
/*!*/ //_SOLO_ para versiones del kernel hasta la 2.6.12
static int checkentry(const char *tablename,
			const struct ipt_ip *ip,
			void *matchinfo,
			unsigned int matchinfosize,
			unsigned int hook_mask) 
{
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)matchinfo;
	
	if (matchinfosize != IPT_ALIGN(sizeof (*info)))
		return 0;
	/* 
	 * Adds a rule to list only if it doesn't exist. 
	 */
	if (!add_rule(info)) {
		printk(KERN_ERR MOD "add_rule() error in checkentry() function.\n");
		return 0;
	}
	return 1;
}

static void destroy(void *matchinfo, unsigned int matchinfosize) 
{
	struct ipt_pknock_info *info = (void *)matchinfo;
	/* 
	 * Removes a rule only if it exits and ref_count is equal to 0.
	 */
	remove_rule(info);
}

static struct ipt_match ipt_pknock_match = {
	.name 		= "pknock",
	.match 		= match,
	.checkentry 	= checkentry,
	.destroy	= destroy,
	.me 		= THIS_MODULE
};

static int __init init(void) 
{
	printk(KERN_INFO MOD "register.\n");

	if (!(proc_net_ipt_pknock = proc_mkdir("ipt_pknock", proc_net))) {
		printk(KERN_ERR MOD "proc_mkdir() error in function init().\n");
		return -1;
	}
	return ipt_register_match(&ipt_pknock_match);
}

static void __exit fini(void)
{
	printk(KERN_INFO MOD "unregister.\n");
	remove_proc_entry("ipt_pknock", proc_net);
	ipt_unregister_match(&ipt_pknock_match);
}

module_init(init);
module_exit(fini);

/*
 * $Log: ipt_pknock.c,v $
 * Revision 1.29  2006/06/02 21:04:03  brugge
 * Se elimno la opcion --rmip o --removeip y su tratamiento en las distintas
 * funciones.
 *
 * Revision 1.28  2006/06/02 04:25:39  brugge
 * Correciones menores.
 *
 * Revision 1.27  2006/05/24 06:22:37  brugge
 * Se eliminaron todas las llamdas a spin_lock_bh() y se agregaron sólo a la
 * fc match() y read_proc().
 *
 * Revision 1.26  2006/05/23 16:04:24  brugge
 * Todas las funciones que modificaban alguna lista enlazada, se hicieron
 * reentrantes agregando bloqueos con spin_lock_bh().
 *
 * Revision 1.25  2006/05/22 14:42:07  brugge
 * Se agregó el uso de una entrada en /proc, para ver el estado de los
 * peers de cada regla. Para esto se agregó la fc. read_proc() y se
 * agregó en las fc add_rule() y remove_rule(), las fc.
 * create_proc_read_entry() y remove_proc_entry() respectivamente.
 * En la fc. init() se agregó la fc. proc_mkdir() para crear un directorio
 * en el /proc y en la fc. fini(), la fc. remove_proc_entry().
 *
 * Revision 1.24  2006/05/19 15:01:21  brugge
 * Se hicieron cambios en la fc peer_status_gc(). Es fc, una vez
 * inicializada, actualizaba el timer cada vez que se ejecutaba. Ahora el
 * timer se actualiza cada vez que se ejecuta la fc match().
 *
 * Revision 1.23  2006/05/18 22:14:40  brugge
 * Se agregó en la fc peer_status_gc() la planificación para borrar
 * un peer que hizo un match y nunca más volvió a golpear un puerto
 * requerido.
 *
 * Revision 1.22  2006/05/18 21:33:20  brugge
 * Se implementó la fc peer_status_gc() -> un garbage collector.
 * Cada vez que se crea una regla, se crea un timer asociado. Al expirar este
 * timer se ejecuta una fc (garbage collector) que elimina de cada regla, las
 * entradas en la lista de peer matching status.
 * Se reemplazó la fc list_for_each() por list_for_each_safe(), ya que
 * provocaba un SIGFAULT cuando hacía list_del(pos) al intentar borrar una
 * entrada en la lista peer_status.
 *
 * Revision 1.21  2006/05/17 22:23:26  brugge
 * Correcciones menores.
 *
 * Revision 1.20  2006/05/16 21:33:15  brugge
 * La fc set_peer_status() implementaba dos funcionalidades: la de
 * setear el estado de un peer y la de actualizarlo. Entonces se separaron
 * estas dos funcionalidades en dos fc: set_peer_status() y
 * update_peer_status().
 * Se hicieron modificaciones en la implementación de la fc match(), de
 * acuerdo a estas nuevas fc.
 *
 * Revision 1.19  2006/05/15 21:29:39  brugge
 * Se realizó la conversión de jiffies a segundos.
 * Se implementó en la fc set_peer_status(), el control del tiempo
 * máximo permitido entre coincidencias (match) de puertos.
 *
 * Revision 1.18  2006/05/14 23:32:58  brugge
 * Se eliminaron todas las líneas de código en donde se obtenía la longitud
 * del nombre de una regla mediante strlen(). Esto debido a que se agregó
 * el campo rule_name_len en la estructura ipt_pknock_info.
 *
 * Revision 1.17  2006/05/11 13:29:49  brugge
 * Se renombraron las opciones del módulo.
 *
 * Revision 1.16  2006/05/10 15:17:44  brugge
 * Se agregó en la fc remove_rule() la implementación para borrar, de una
 * regla, los nodos de la lista del estado de matcheo de cada peer.
 *
 * Revision 1.15  2006/05/08 20:42:11  brugge
 * Correcciones menores debido a cambios en el archivo ipt_pknock.h.
 *
 * Revision 1.14  2006/05/08 14:28:10  brugge
 * Se agregó la fc. is_1st_port_match() y se eliminó is_port_match().
 * Se corrigieron las implementaciones de las fc. set_peer_status_match() y
 * match().
 *
 * Revision 1.13  2006/05/05 21:49:05  brugge
 * Se cambiaron los nombre de las funciones *_peer_status por
 * *_peer_status.
 * Se corrigió la implementación de la fc. set_peer_matching_support().
 * Se corrigió la implementación de la fc. match().
 *
 * Revision 1.12  2006/05/05 12:05:14  brugge
 * Se modificó la fc. check_peer_status().
 * Se hicieron correcciones menores.
 * Versión estable.
 *
 * Revision 1.11  2006/05/04 20:21:27  brugge
 * Se agregaron las funciones: new_peer_status(), add_peer_status(),
 * remove_peer_status(), check_peer_status() y set_peer_status().
 * Se modificó la implementación de la fc. match().
 * Se hicieron correcciones menores.
 *
 * Revision 1.10  2006/05/04 00:17:33  brugge
 * Se agregó la fc. search_rule().
 * Se corrigió un error en la fc. destroy().
 * Se inició la implementación de la fc. match().
 *
 * Revision 1.9  2006/04/29 04:45:04  brugge
 * Se corrigió la implementación de add_rule() y remove_rule().
 * Al no inicializar los punteros next y prev de la cabeza de la lista, cuando
 * intentaba recorrer la lista obtenía un segmentation fault.
 *
 * Revision 1.7  2006/04/28 20:29:56  brugge
 * Se implementaron parte de las funciones checkentry() y destroy().
 * Se agregaron las funciones add_rule() y remove_rule(), las cuales son
 * llamadas desde checkentry() y destroy() respectivamente.
 *
 * Revision 1.6  2006/04/26 18:33:44  brugge
 * Se agregó la fc. destroy().
 * Se modificó la fc. print_ip_packet().
 *
 * Revision 1.5  2006/04/17 21:18:30  brugge
 * Se agregaron las funciones is_port_match() y print_ip_packet().
 * Se agregó el tratamiento de los protocolos tcp y udp en la función match().
 *
 * Revision 1.4  2006/04/17 03:37:38  brugge
 * Correcciones menores.
 *
 * Revision 1.3  2006/04/16 21:08:40  brugge
 * Se implementó el resto de las funciones.
 *
 * Revision 1.2  2006/04/16 14:50:28  brugge
 * Se colocaron un par de printk() en la fc match() para debugging.
 *
 * Revision 1.1  2006/04/11 00:44:09  brugge
 * Versión inicial.
 *
 */
