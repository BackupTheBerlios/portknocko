/*
 * Kernel module to implement port knocking matching support.
 * 
 * (C) 2006 J. Federico Hernandez Scarso <fede.hernandez@gmail.com>
 * (C) 2006 Luis A. Floreani <luis.floreani@gmail.com>
 *
 * $Id$
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
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/jiffies.h>
#include <linux/timer.h>

#include <linux/netfilter_ipv4/ip_tables.h>
//#include <linux/netfilter_ipv4/ipt_pknock.h>
#include "ipt_pknock.h"

#if NETLINK_MSG
#include <linux/connector.h>
#endif

MODULE_AUTHOR("J. Federico Hernandez Scarso, Luis A. Floreani");
MODULE_DESCRIPTION("iptables/netfilter's port knocking match module");
MODULE_LICENSE("GPL");

#define GC_EXPIRATION_TIME 30000 /* in msecs */

#define DEFAULT_RULE_HASH_SIZE 8
#define DEFAULT_PEER_HASH_SIZE 16

#define NL_MULTICAST_GROUP 1

#define hashtable_for_each_safe(pos, n, head, size, i) \
	for ((i) = 0; (i) < (size); (i)++) \
		list_for_each_safe((pos), (n), (&head[(i)]))

static u_int32_t ipt_pknock_hash_rnd;

static unsigned int ipt_pknock_rule_htable_size = DEFAULT_RULE_HASH_SIZE;
static unsigned int ipt_pknock_peer_htable_size = DEFAULT_PEER_HASH_SIZE;

static unsigned int ipt_pknock_gc_expir_time 	= GC_EXPIRATION_TIME;

static struct list_head *rule_hashtable = NULL;

static DEFINE_SPINLOCK(rule_list_lock);
static struct proc_dir_entry *proc_net_ipt_pknock = NULL;

static char *algo = "md5";

/**
 * Calculates a value from 0 to max from a hash of the arguments.
 * 
 * @key
 * @length
 * @initval
 * @max
 * @return: ?
 */
static u_int32_t pknock_hash(const void *key, u_int32_t length, u_int32_t initval, u_int32_t max) {
	return jhash(key, length, initval) % max;
}

/**
 * Alloc a hashtable with n buckets.
 * 
 * @size
 * return: hash
 */
static struct list_head *alloc_hashtable(int size) {
	struct list_head *hash = NULL;
	unsigned int i;

	if ((hash = kmalloc(sizeof(struct list_head) * size, GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in alloc_hashtable() function.\n");
		return NULL;
	}

	for (i = 0; i < size; i++)
		INIT_LIST_HEAD(&hash[i]);
#if DEBUG
	printk(KERN_DEBUG MOD "%d buckets created. \n", size);
#endif				
	return hash;
}

#if DEBUG
/**
 * @iph
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
#endif

/**
 * This function converts the status from integer to string.
 *
 * @status
 * @return: status
 */
static inline const char *status_itoa(enum status status) {
	switch (status) {
		case ST_INIT: return "INIT";
		case ST_MATCHING: return "MATCHING";
		case ST_ALLOWED: return "ALLOWED";
	}
	return "UNKNOWN";
}

/**
 * This function produces the peer matching status data when the file is read.
 *
 * @buf
 * @start
 * @offset
 * @count
 * @eof
 * @data
 */
static int read_proc(char *buf, char **start, off_t offset, int count, int *eof, void *data) {
	int limit = count, len = 0, i;
	off_t pos = 0, begin = 0;
	u_int32_t ip;
	const char *status = NULL, *proto = NULL;
	struct list_head *p = NULL, *n = NULL;
	struct ipt_pknock_rule *rule = NULL;
	struct peer *peer = NULL;
	unsigned long expiration_time = 0, max_time = 0;

	*eof=0;

	spin_lock_bh(&rule_list_lock);

	rule = (struct ipt_pknock_rule *)data;

	max_time = rule->max_time;

	hashtable_for_each_safe(p, n, rule->peer_head, ipt_pknock_peer_htable_size, i) {
		peer = list_entry(p, struct peer, head);

		status = status_itoa(peer->status);

		proto = (peer->proto == IPPROTO_TCP) ? "TCP" : "UDP";
		ip = htonl(peer->ip);

		expiration_time = time_before(jiffies/HZ, peer->timestamp + max_time) ?
			((peer->timestamp + max_time)-(jiffies/HZ)) : 0;

		len += snprintf(buf+len, limit-len, "src=%u.%u.%u.%u ", NIPQUAD(ip));
		len += snprintf(buf+len, limit-len, "proto=%s ", proto);
		len += snprintf(buf+len, limit-len, "status=%s ", status);
		len += snprintf(buf+len, limit-len, "expiration_time=%ld ", 
				expiration_time);
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

/**
 * Garbage collector. It removes the old entries after that the timer has expired.
 *
 * @r: rule
 */
static void peer_gc(unsigned long r) {
	int i;
	struct ipt_pknock_rule *rule = (struct ipt_pknock_rule *)r;
	struct peer *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;
	
	hashtable_for_each_safe(pos, n, rule->peer_head, ipt_pknock_peer_htable_size, i) {
		peer = list_entry(pos, struct peer, head);
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

/**
 * Compares length and name equality for the rules.
 * 
 * @info
 * @rule
 * @return: 0 success, 1 failure
 */
static inline int rulecmp(struct ipt_pknock_info *info, struct ipt_pknock_rule *rule) {
	if (info->rule_name_len != rule->rule_name_len)
		return 1;
	if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) != 0)
		return 1;

	return 0;
}

/**
 * Search the rule and returns a pointer if it exists.
 *
 * @info
 * @return: rule or NULL
 */
static inline struct ipt_pknock_rule * search_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, 
				ipt_pknock_hash_rnd, ipt_pknock_rule_htable_size);

	if (!list_empty(&rule_hashtable[hash])) {
		list_for_each_safe(pos, n, &rule_hashtable[hash]) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);

			if (rulecmp(info, rule) == 0)
				return rule;
		}		
	}

	return NULL;
}

/**
 * It adds a rule to list only if it doesn't exist.
 *
 * @info
 * @return: 1 success, 0 failure
 */
static int add_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, 
				ipt_pknock_hash_rnd, ipt_pknock_rule_htable_size);

	if (!list_empty(&rule_hashtable[hash])) {
		list_for_each_safe(pos, n, &rule_hashtable[hash]) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);
			/* If the rule exists. */
			if (rulecmp(info, rule) == 0) {
				rule->ref_count++;
				
				if (info->option & IPT_PKNOCK_CHECK) {
					printk(KERN_DEBUG MOD "add_rule() (AC) rule found: %s - ref_count: %d\n", rule->rule_name, rule->ref_count);
				 
					 return 1;
				 }
#if DEBUG
				printk(KERN_DEBUG MOD "add_rule() (E) rule found: %s - ref_count: %d\n", rule->rule_name, rule->ref_count);
#endif				
				return 1;
			}
		}
	}
	/*  If it doesn't exist. */
	if ((rule = (struct ipt_pknock_rule *)kmalloc(sizeof (*rule), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in add_rule() function.\n");
		return 0;
	}

	INIT_LIST_HEAD(&rule->head);
	memset(rule->rule_name, 0, IPT_PKNOCK_MAX_BUF_LEN);
	strncpy(rule->rule_name, info->rule_name, info->rule_name_len);
	rule->rule_name_len = info->rule_name_len;
	rule->ref_count	= 1;
	rule->max_time 	= info->max_time;

	rule->peer_head = alloc_hashtable(ipt_pknock_peer_htable_size);

	init_timer(&rule->timer);
	rule->timer.function 	= peer_gc;
	rule->timer.data	= (unsigned long)rule;

	if (!(rule->status_proc = create_proc_read_entry(info->rule_name, 0, 
					proc_net_ipt_pknock, read_proc, rule))) {
		printk(KERN_ERR MOD "create_proc_entry() error in add_rule() function.\n");
		if (rule) kfree(rule);
		return 0;
	}

	list_add(&rule->head, &rule_hashtable[hash]);
#if DEBUG
	printk(KERN_INFO MOD "(A) rule_name: %s - created.\n", rule->rule_name);
#endif	
	return 1;

}


/**
 * It removes a rule only if it exists.
 *
 * @info
 */
static void remove_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;
	struct peer *peer = NULL;
	int i, found = 0;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, 
				ipt_pknock_hash_rnd, ipt_pknock_rule_htable_size);

	if (list_empty(&rule_hashtable[hash])) return;

	list_for_each_safe(pos, n, &rule_hashtable[hash]) {
		rule = list_entry(pos, struct ipt_pknock_rule, head);
		/* If the rule exists. */
		if (rulecmp(info, rule) == 0) {
			found = 1;
			rule->ref_count--;
			break;
		}
	}
	
	if (!found) {
#if DEBUG
		printk(KERN_INFO MOD "(N) rule not found: %s.\n", info->rule_name);
#endif
		return;
	}

	if (rule != NULL && rule->ref_count == 0) {
		hashtable_for_each_safe(pos, n, rule->peer_head, ipt_pknock_peer_htable_size, i) {
			peer = list_entry(pos, struct peer, head);
			if (peer != NULL) {
#if DEBUG	
				printk(KERN_INFO MOD "(D) peer deleted: %u.%u.%u.%u\n", 
						NIPQUAD(peer->ip));
#endif				
				list_del(pos);
				kfree(peer);
			}
		}
		if (rule->status_proc) remove_proc_entry(info->rule_name, proc_net_ipt_pknock);
#if DEBUG
		printk(KERN_INFO MOD "(D) rule deleted: %s.\n", rule->rule_name);
#endif
		if (timer_pending(&rule->timer)) {
			del_timer(&rule->timer);
		}

		list_del(&rule->head);
		kfree(rule->peer_head);
		kfree(rule);
	}

}

/**
 * It updates the rule timer to execute garbage collector.
 *
 * @rule
 */
static inline void update_rule_timer(struct ipt_pknock_rule *rule) {
	if (timer_pending(&rule->timer)) {
		del_timer(&rule->timer);
	}
	rule->timer.expires = jiffies + msecs_to_jiffies(ipt_pknock_gc_expir_time);
	add_timer(&rule->timer);
}

/**
 * If peer status exist in the list it returns peer status, if not it returns NULL.
 *
 * @rule
 * @ip
 * @return: peer or NULL
 */
static inline struct peer * get_peer(struct ipt_pknock_rule *rule, u_int32_t ip) {
	struct peer *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;
	int hash;

	ip = ntohl(ip);

	hash = pknock_hash(&ip, sizeof(u_int32_t), ipt_pknock_hash_rnd, ipt_pknock_peer_htable_size);

	if (list_empty(&rule->peer_head[hash])) return NULL;

	list_for_each_safe(pos, n, &rule->peer_head[hash]) {
		peer = list_entry(pos, struct peer, head);
		if (peer->ip == ip) return peer;
	}
	return NULL;
}


/**
 * Reset the knock sequence status of the peer.
 * 
 * @peer
 */
static inline void reset_knock_status(struct peer *peer) {
	peer->id_port_knocked = 1;
}

/**
 * It creates a new peer matching status.
 *
 * @rule
 * @ip
 * @proto
 * @return: peer or NULL
 */
static inline struct peer * new_peer(u_int32_t ip, u_int8_t proto) {
	struct peer *peer = NULL;

	if ((peer = (struct peer *)kmalloc(sizeof (*peer), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in new_peer() function.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&peer->head);
	peer->ip 	= ntohl(ip);
	peer->proto 	= proto;
	peer->status 	= ST_INIT;
	peer->timestamp = jiffies/HZ;
	reset_knock_status(peer);

	return peer;
}



/**
 * It adds a new peer matching status to the list.
 *
 * @peer
 * @rule
 */
static inline void add_peer(struct peer *peer, struct ipt_pknock_rule *rule) {
	int hash = pknock_hash(&peer->ip, sizeof(u_int32_t), 
				ipt_pknock_hash_rnd, ipt_pknock_peer_htable_size);
#if DEBUG
	printk(KERN_DEBUG MOD "add_peer() -> hash %d \n", hash);
#endif				
	list_add(&peer->head, &rule->peer_head[hash]);

	peer->timestamp = jiffies/HZ;
	peer->status = ST_MATCHING;
}

/**
 * It removes a peer matching status.
 *
 * @peer
 */
static inline void remove_peer(struct peer *peer) {
	list_del(&peer->head);
	if (peer) kfree(peer);
}

static inline int is_first_knock(struct peer *peer, struct ipt_pknock_info *info, u_int16_t port) {
	return (peer == NULL && info->port[0] == port) ? 1 : 0;
}

static inline int is_wrong_knock(struct peer *peer, struct ipt_pknock_info *info, u_int16_t port) {
	return info->port[peer->id_port_knocked-1] != port;
}

static inline int is_last_knock(struct peer *peer, struct ipt_pknock_info *info) {
	return peer->id_port_knocked-1 == info->count_ports;
}

static inline int is_allowed(struct peer *peer) {
	return (peer && peer->status == ST_ALLOWED) ? 1 : 0;
}


/**
 * Sends a message to user space through netlink sockets.
 * 
 * @info
 */
#if NETLINK_MSG
void msg_to_userspace_nl(struct ipt_pknock_info *info, struct peer *peer) {
	struct cn_msg *m;
    	struct cb_id cn_test_id = { 0x123, 0x345 };
	struct ipt_pknock_nl_msg nlmsg;
    
    	m = kmalloc(sizeof(*m) + sizeof(nlmsg), GFP_ATOMIC);
    	if (m) {
        	memset(m, 0, sizeof(*m) + sizeof(nlmsg));
	        memcpy(&m->id, &cn_test_id, sizeof(m->id));

        	m->seq = 0;		
		m->len = sizeof(nlmsg);

		nlmsg.peer_ip = peer->ip;
		scnprintf(nlmsg.rule_name, info->rule_name_len + 1, info->rule_name);
		
	        memcpy(m + 1, (char *)&nlmsg, m->len);
        
	        cn_netlink_send(m, NL_MULTICAST_GROUP, gfp_any());
        
		kfree(m);
	} 
}
#endif

/**
 * It updates the peer matching status.
 *
 * @peer
 * @info
 * @port
 * @return: 1 if allowed, 0 otherwise
 */
static int update_peer(struct peer *peer, struct ipt_pknock_info *info, u_int16_t port) {
	unsigned long time;

	if (is_allowed(peer)) {
#if DEBUG
		printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - PASS OK.\n", NIPQUAD(peer->ip));
#endif
		return 1;
	}

	if (is_wrong_knock(peer, info, port)) {
#if DEBUG
		printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - DIDN'T MATCH.\n", NIPQUAD(peer->ip));
#endif
		if ((info->option & IPT_PKNOCK_STRICT)) {
			/* Peer must start the sequence from scratch. */
			reset_knock_status(peer);
		}
		return 0;
	}

	peer->id_port_knocked++;

	if (is_last_knock(peer, info)) {
		peer->status = ST_ALLOWED;
#if DEBUG
		printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - ALLOWED.\n", NIPQUAD(peer->ip));	
#endif

#if NETLINK_MSG		
		/* Send a msg to userspace saying the peer knocked all the sequence correcty! */
		msg_to_userspace_nl(info, peer);
#endif

		return 0;
	}

	/* Controls the max matching time between ports. */
	if (info->option & IPT_PKNOCK_TIME) {
		time = jiffies/HZ;
		/* Returns true if the time a is after time b. */
		if (time_after(time, peer->timestamp + info->max_time)) {
#if DEBUG
			printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - TIME EXCEEDED.\n", NIPQUAD(peer->ip));
			printk(KERN_INFO MOD "(X) peer: %u.%u.%u.%u - DESTROYED.\n", NIPQUAD(peer->ip));
			printk(KERN_INFO MOD "max_time: %ld - time: %ld\n", 
					peer->timestamp + info->max_time, time);
#endif
			remove_peer(peer);
			return 0;
		}
		peer->timestamp = time;		
	}
#if DEBUG
	printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - MATCHING.\n", 
			NIPQUAD(peer->ip));
#endif
	return 0;
}

/**
 * Prints any sequence of characters as hexadecimal.
 *
 * @buf
 * @len
 */
static void hexdump(unsigned char *buf, unsigned int len /*md5: 16*/) {
	while (len--)
		printk("%02x", *buf++);
	printk("\n");
}

/**
 * Transforms a sequence of characters to hexadecimal.
 *
 * @out: the hexadecimal result
 * @crypt: the original sequence
 * @size
 */
static void crypt_to_hex(char *out, char *crypt, int size) {
	int i;
	for (i=0; i < size; i++) {
		unsigned char c = crypt[i];
		*out++ = '0' + ((c&0xf0)>>4) + (c>=0xa0)*('a'-'9'-1);
		*out++ = '0' + (c&0x0f) + ((c&0x0f)>=0x0a)*('a'-'9'-1);
	}
}


/**
 * Checks that the payload has the hmac(secret+ipsrc).
 *
 * @secret
 * @secret_len
 * @ipsrc
 * @payload
 * @payload_len
 */
static int has_secret(unsigned char *secret, int secret_len, u_int32_t ipsrc, unsigned char *payload, int payload_len) {
	struct scatterlist sg[2];
	char result[64];
	char *hexresult;
	struct crypto_tfm *tfm;

	int hexa_size;
	int crypt_size;
	int ret = 1;

	if (payload_len == 0)
		return 0;

	tfm = crypto_alloc_tfm(algo, 0);	

	if (tfm == NULL) {
		printk(KERN_INFO MOD "failed to load transform for %s\n", algo);
		return 0;
	}

	crypt_size = crypto_tfm_alg_digestsize(tfm);

	hexa_size = crypt_size * 2;

	if (payload_len != hexa_size) {
		return 0;
	}

	if ((hexresult = kmalloc((sizeof(char) * hexa_size), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in has_secret() function.\n");
		return -EINVAL;
	}

	memset(result, 0, 64);
	memset(hexresult, 0, (sizeof(char) * hexa_size));

	sg_set_buf(&sg[0], &ipsrc, sizeof(u_int32_t));

	crypto_hmac(tfm, secret, &secret_len, sg, 1, result);

	crypt_to_hex(hexresult, result, crypt_size);

	if (memcmp(hexresult, payload, hexa_size) != 0) { 
#if DEBUG
		printk(KERN_INFO MOD "payload len: %d\n", payload_len);
		printk(KERN_INFO MOD "secret match failed\n");
#endif
		ret = 0;
		goto end;
	}

end:	
	kfree(hexresult);
	crypto_free_tfm(tfm);	
	return ret;
}


static int match(const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const void *matchinfo,
		int offset,
		int *hotdrop) 
{
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)matchinfo;
	struct ipt_pknock_rule *rule = NULL;
	struct peer *peer = NULL;
	struct iphdr *iph = skb->nh.iph;
	int iphl = iph->ihl * 4;
	void *transph = (void *)iph + iphl;		/* tranport protocol header */
	u_int16_t port = 0;
	u_int8_t proto = 0;
	int ret=0;	
	unsigned char *payload;
	int payload_len;
	int headers_len;

	switch ((proto = iph->protocol)) {
		case IPPROTO_TCP:
			port = ntohs(((struct tcphdr *)transph)->dest); 
			headers_len = iphl + sizeof(struct tcphdr);
			break;

		case IPPROTO_UDP:
			port = ntohs(((struct udphdr *)transph)->dest);
			headers_len = iphl + sizeof(struct udphdr);
			break;

		default:
			printk(KERN_INFO MOD "IP payload protocol is neither tcp nor udp.\n");
			goto end;
	}

	spin_lock_bh(&rule_list_lock);

	/* Searches a rule from the list depending on info structure options. */
	if ((rule = search_rule(info)) == NULL) {
		printk(KERN_INFO MOD "The rule %s doesn't exist.\n", info->rule_name);
		goto end;
	}
	
	/* Updates the rule timer to execute the garbage collector. */
	update_rule_timer(rule);
	
	/* Gives the peer matching status added to rule depending on ip source. */
	peer = get_peer(rule, iph->saddr);

	if ((info->option & IPT_PKNOCK_CHECK)) {
		ret = is_allowed(peer);
#if DEBUG
		if (ret) {
			printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - PASS OK CHECKED.\n", NIPQUAD(peer->ip));
		}
#endif
		goto end;
	}

	/* If security is needed and the peer is still knocking ... */
	if ((info->option & IPT_PKNOCK_SECURE) && !is_allowed(peer)) {
		if (iph->protocol != IPPROTO_UDP) {
			printk(KERN_INFO MOD "FAIL: proto must be UDP when --secure.\n");
			goto end;
		}

		payload = (void *)iph + headers_len;
		payload_len = skb->len - headers_len;
		if (!has_secret(info->password, info->password_len, iph->saddr, payload, payload_len))
			goto end;
	}
	
	/* Sets, updates, removes or checks the peer matching status. */
	if (info->option & IPT_PKNOCK_KNOCKPORT) {
		if (is_first_knock(peer, info, port)) {
			peer = new_peer(iph->saddr, proto);
			add_peer(peer, rule);
		} 

		if (peer != NULL) {
			ret = update_peer(peer, info, port);
			goto end;
		}
	}

end:
	spin_unlock_bh(&rule_list_lock);
	return ret;
}

static int checkentry(const char *tablename,
		const struct ipt_ip *ip,
		void *matchinfo,
		unsigned int matchinfosize,
		unsigned int hook_mask) 
{
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)matchinfo;

	if (matchinfosize != IPT_ALIGN(sizeof (*info)))
		return 0;

	if (!rule_hashtable) {
		rule_hashtable = alloc_hashtable(ipt_pknock_rule_htable_size);
		get_random_bytes(&ipt_pknock_hash_rnd, sizeof (u_int32_t));
	}

	if (!add_rule(info)) {
		printk(KERN_ERR MOD "add_rule() error in checkentry() function.\n");
		return 0;
	}
	return 1;
}

static void destroy(void *matchinfo, unsigned int matchinfosize) 
{
	struct ipt_pknock_info *info = (void *)matchinfo;

	/* Removes a rule only if it exits and ref_count is equal to 0. */
	remove_rule(info);
}

static struct ipt_match ipt_pknock_match = {
	.name 		= "pknock",
	.match 		= match,
	.checkentry 	= checkentry,
	.destroy	= destroy,
	.me 		= THIS_MODULE
};

static int set_rule_hashsize(const char *val, struct kernel_param *kp) {
	unsigned int hashsize;

	hashsize = simple_strtol(val, NULL, 0);

	if (!hashsize) return -EINVAL;

	ipt_pknock_rule_htable_size = hashsize;

	return 0;
}

static int set_peer_hashsize(const char *val, struct kernel_param *kp) {
	unsigned int hashsize;

	hashsize = simple_strtol(val, NULL, 0);

	if (!hashsize) return -EINVAL;

	ipt_pknock_peer_htable_size = hashsize;

	return 0;
}	

static int set_gc_expir_time(const char *val, struct kernel_param *kp) {
	unsigned int gc_expir_time;	/* in seconds */

	gc_expir_time = simple_strtol(val, NULL, 0);

	if (!gc_expir_time) return -EINVAL;

	ipt_pknock_gc_expir_time = gc_expir_time * 1000;
		
	return 0;
}	

module_param_call(rule_hashsize, set_rule_hashsize, param_get_uint, &ipt_pknock_rule_htable_size, 0600);
module_param_call(peer_hashsize, set_peer_hashsize, param_get_uint, &ipt_pknock_peer_htable_size, 0600);
module_param_call(gc_expir_time, set_gc_expir_time, param_get_uint, &ipt_pknock_gc_expir_time, 0600); 

static int __init ipt_pknock_init(void) 
{
	printk(KERN_INFO MOD "register.\n");

	if (!(proc_net_ipt_pknock = proc_mkdir("ipt_pknock", proc_net))) {
		printk(KERN_ERR MOD "proc_mkdir() error in function init().\n");
		return -1;
	}
	return ipt_register_match(&ipt_pknock_match);
}

static void __exit ipt_pknock_fini(void)
{
	printk(KERN_INFO MOD "unregister.\n");
	remove_proc_entry("ipt_pknock", proc_net);
	ipt_unregister_match(&ipt_pknock_match);

	kfree(rule_hashtable);
}

module_init(ipt_pknock_init);
module_exit(ipt_pknock_fini);
