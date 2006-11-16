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
#include <linux/in.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/seq_file.h>

#include <linux/netfilter_ipv4/ip_tables.h>
//#include <linux/netfilter_ipv4/ipt_pknock.h>
#include "ipt_pknock.h"

#if NETLINK_MSG
#include <linux/connector.h>
#endif

MODULE_AUTHOR("J. Federico Hernandez Scarso, Luis A. Floreani");
MODULE_DESCRIPTION("iptables/netfilter's port knocking match module");
MODULE_LICENSE("GPL");

enum {
	GC_EXPIRATION_TIME = 65000, /* in msecs */
	DEFAULT_RULE_HASH_SIZE = 8,
	DEFAULT_PEER_HASH_SIZE = 16,
};

#define hashtable_for_each_safe(pos, n, head, size, i) \
	for ((i) = 0; (i) < (size); (i)++) \
		list_for_each_safe((pos), (n), (&head[(i)]))

#if DEBUG
	#define DEBUGP(msg, peer) printk(KERN_INFO MOD \
			"(S) peer: %u.%u.%u.%u - %s.\n",  \
			NIPQUAD((peer)->ip), msg)
#else
	#define DEBUGP(msg, peer)
#endif

static u_int32_t ipt_pknock_hash_rnd;

static unsigned int rule_hashsize = DEFAULT_RULE_HASH_SIZE;
static unsigned int peer_hashsize = DEFAULT_PEER_HASH_SIZE;
static int nl_multicast_group = -1;

static unsigned int ipt_pknock_gc_expir_time 	= GC_EXPIRATION_TIME;

static struct list_head *rule_hashtable = NULL;

static DEFINE_SPINLOCK(list_lock);
static struct proc_dir_entry *pde = NULL;

static struct ipt_pknock_crypto crypto = { 
	.algo 	= "sha256",
	.tfm 	= NULL,
	.size 	= 0
};

module_param(rule_hashsize, int, S_IRUGO);
module_param(peer_hashsize, int, S_IRUGO);
module_param(ipt_pknock_gc_expir_time, int, S_IRUGO);
module_param(nl_multicast_group, int, S_IRUGO);


/**
 * Calculates a value from 0 to max from a hash of the arguments.
 * 
 * @key
 * @len: length
 * @initval
 * @max
 * @return: a 32 bits index
 */
static u_int32_t 
pknock_hash(const void *key, u_int32_t len, u_int32_t initval, u_int32_t max)
{
	return jhash(key, len, initval) % max;
}

/**
 * @return: the epoch minute
 */
static int 
get_epoch_minute(void) 
{
	struct timespec t;
	t = CURRENT_TIME;
	return (int)(t.tv_sec/60);
}

/**
 * Alloc a hashtable with n buckets.
 * 
 * @size
 * @return: hashtable
 */
static struct list_head *
alloc_hashtable(int size) 
{
	struct list_head *hash = NULL;
	unsigned int i;

	if ((hash = kmalloc(sizeof(*hash) * size, GFP_ATOMIC)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in alloc_hashtable() function.\n");
		return NULL;
	}

	for (i = 0; i < size; i++) {
		INIT_LIST_HEAD(&hash[i]);
	}

	return hash;
}

#if DEBUG
/**
 * @iph
 */
static inline void 
print_ip_packet(struct iphdr *iph) 
{
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
static inline const char *
status_itoa(enum status status) 
{
	switch (status) {
		case ST_INIT: return "INIT";
		case ST_MATCHING: return "MATCHING";
		case ST_ALLOWED: return "ALLOWED";
	}
	return "UNKNOWN";
}

/**
 * @s
 * @pos
 * @return: private value used by the iterator
 */
static void *
pknock_seq_start(struct seq_file *s, loff_t *pos)
{
	struct proc_dir_entry *pde = s->private;
	struct ipt_pknock_rule *rule = pde->data;

	spin_lock_bh(&list_lock);
	
	if (*pos >= peer_hashsize)
		return NULL;

	return rule->peer_head + *pos;
}

/**
 * @s
 * @v
 * @pos
 * @return: next value for the iterator
 */
static void *
pknock_seq_next(struct seq_file *s, void *v, loff_t *pos) 
{
	struct proc_dir_entry *pde = s->private;
	struct ipt_pknock_rule *rule = pde->data;

	(*pos)++;
	if (*pos >= peer_hashsize) {
		return NULL;
	}
	
	return rule->peer_head + *pos;
}

/**
 * @s
 * @v
 */
static void 
pknock_seq_stop(struct seq_file *s, void *v) 
{	
	spin_unlock_bh(&list_lock);
}


/**
 * @s
 * @v
 * @return: 0 if OK
 */
static int 
pknock_seq_show(struct seq_file *s, void *v) 
{
	struct list_head *pos = NULL, *n = NULL;
	struct peer *peer = NULL;
	unsigned long expir_time = 0;	
        u_int32_t ip;
	
	struct list_head *peer_head = (struct list_head *)v;

	struct proc_dir_entry *pde = s->private;
	struct ipt_pknock_rule *rule = pde->data;

	list_for_each_safe(pos, n, peer_head) {
		peer = list_entry(pos, struct peer, head);
		ip = htonl(peer->ip);
		expir_time = time_before(jiffies/HZ, peer->timestamp + rule->max_time)
			? ((peer->timestamp + rule->max_time)-(jiffies/HZ)) : 0;

		seq_printf(s, "src=%u.%u.%u.%u ", NIPQUAD(ip));
		seq_printf(s, "proto=%s ", (peer->proto == IPPROTO_TCP) ? "TCP" : "UDP");
		seq_printf(s, "status=%s ", status_itoa(peer->status));
		seq_printf(s, "expir_time=%ld ", expir_time);
		seq_printf(s, "next_port_id=%d ", peer->id_port_knocked-1);
		seq_printf(s, "\n");
	}
	
	return 0;
}

static struct seq_operations pknock_seq_ops = {
	.start = pknock_seq_start,
	.next = pknock_seq_next,
	.stop = pknock_seq_stop,
	.show = pknock_seq_show
};

/**
 * @inode
 * @file
 */
static int 
pknock_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &pknock_seq_ops);
	if (!ret) {
        	struct seq_file *sf = file->private_data;
		sf->private = PDE(inode);
	}
	return ret;	
}

static struct file_operations pknock_proc_ops = {
	.owner = THIS_MODULE,
	.open = pknock_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

/**
 * It updates the rule timer to execute garbage collector.
 *
 * @rule
 */
static inline void 
update_rule_timer(struct ipt_pknock_rule *rule) 
{
	if (timer_pending(&rule->timer))
		del_timer(&rule->timer);

	rule->timer.expires = jiffies + msecs_to_jiffies(ipt_pknock_gc_expir_time);
	add_timer(&rule->timer);
}

/**
 * @peer
 * @max_time
 * @return: 1 time exceeded, 0 still valid
 */ 
static inline int 
is_time_exceeded(struct peer *peer, int max_time)
{
	return time_after(jiffies/HZ, peer->timestamp + max_time);
}

/**
 * @peer
 * @return: 1 has logged, 0 otherwise
 */
static int 
has_logged_during_this_minute(const struct peer *peer) 
{
	return peer && (peer->login_min == get_epoch_minute());
}

/**
 * Garbage collector. It removes the old entries after timer has expired.
 *
 * @r: rule
 */
static void 
peer_gc(unsigned long r) 
{
	int i;
	struct ipt_pknock_rule *rule = (struct ipt_pknock_rule *)r;
	struct peer *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;

	hashtable_for_each_safe(pos, n, rule->peer_head, 
			peer_hashsize, i) {
		
		peer = list_entry(pos, struct peer, head);
		
		if (!has_logged_during_this_minute(peer) && 
				is_time_exceeded(peer, rule->max_time)) {
			DEBUGP("DESTROYED", peer);	
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
 * @return: 0 equals, 1 otherwise
 */
static inline int 
rulecmp(const struct ipt_pknock_info *info, const struct ipt_pknock_rule *rule)
{
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
static inline struct ipt_pknock_rule * 
search_rule(const struct ipt_pknock_info *info)
{
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, 
			ipt_pknock_hash_rnd, rule_hashsize);

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
static int 
add_rule(struct ipt_pknock_info *info) 
{
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, 
			ipt_pknock_hash_rnd, rule_hashsize);

	if (!list_empty(&rule_hashtable[hash])) {
		list_for_each_safe(pos, n, &rule_hashtable[hash]) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);
			
			if (rulecmp(info, rule) == 0) {
				rule->ref_count++;
#if DEBUG				
				if (info->option & IPT_PKNOCK_CHECKIP) {
					printk(KERN_DEBUG MOD "add_rule() (AC)"
						" rule found: %s - "
						"ref_count: %d\n",
						rule->rule_name, 
						rule->ref_count);
				}
#endif
				return 1;
			}
		}
	}
	
	if ((rule = kmalloc(sizeof (*rule), GFP_ATOMIC)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in add_rule().\n");
		return 0;
	}

	INIT_LIST_HEAD(&rule->head);
	memset(rule->rule_name, 0, IPT_PKNOCK_MAX_BUF_LEN);
	strncpy(rule->rule_name, info->rule_name, info->rule_name_len);
	rule->rule_name_len = info->rule_name_len;
	rule->ref_count	= 1;
	rule->max_time 	= info->max_time;

	rule->peer_head = alloc_hashtable(peer_hashsize);

	init_timer(&rule->timer);
	rule->timer.function 	= peer_gc;
	rule->timer.data	= (unsigned long)rule;

	rule->status_proc = create_proc_entry(info->rule_name, 0, pde);
	if (!rule->status_proc) {
		printk(KERN_ERR MOD "create_proc_entry() error in add_rule() function.\n");
                kfree(rule);
                return -1;		
	}

	rule->status_proc->proc_fops = &pknock_proc_ops;
	rule->status_proc->data = rule;
	
	list_add(&rule->head, &rule_hashtable[hash]);
#if DEBUG
	printk(KERN_INFO MOD "(A) rule_name: %s - created.\n", 
			rule->rule_name);
#endif	
	return 1;

}


/**
 * It removes a rule only if it exists.
 *
 * @info
 */
static void 
remove_rule(struct ipt_pknock_info *info) 
{
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;
	struct peer *peer = NULL;
	int i;
#if DEBUG	
	int found = 0;
#endif
	int hash = pknock_hash(info->rule_name, info->rule_name_len, 
			ipt_pknock_hash_rnd, rule_hashsize);

	if (list_empty(&rule_hashtable[hash])) return;

	list_for_each_safe(pos, n, &rule_hashtable[hash]) {
		rule = list_entry(pos, struct ipt_pknock_rule, head);
		
		if (rulecmp(info, rule) == 0) {
#if DEBUG
			found = 1;
#endif			
			rule->ref_count--;
			break;
		}
	}
#if DEBUG	
	if (!found) {
		printk(KERN_INFO MOD "(N) rule not found: %s.\n", 
				info->rule_name);
		return;
	}
#endif
	if (rule != NULL && rule->ref_count == 0) {
		hashtable_for_each_safe(pos, n, rule->peer_head, 
				peer_hashsize, i) {
			peer = list_entry(pos, struct peer, head);
			if (peer != NULL) {
				DEBUGP("DELETED", peer);			
				list_del(pos);
				kfree(peer);
			}
		}
		if (rule->status_proc) 
			remove_proc_entry(info->rule_name, pde);
#if DEBUG
		printk(KERN_INFO MOD "(D) rule deleted: %s.\n", 
				rule->rule_name);
#endif
		if (timer_pending(&rule->timer))
			del_timer(&rule->timer);

		list_del(&rule->head);
		kfree(rule->peer_head);
		kfree(rule);
	}
}

/**
 * If peer status exist in the list it returns peer status, if not it returns NULL.
 *
 * @rule
 * @ip
 * @return: peer or NULL
 */
static inline struct peer * 
get_peer(struct ipt_pknock_rule *rule, u_int32_t ip) 
{
	struct peer *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;
	int hash;

	ip = ntohl(ip);

	hash = pknock_hash(&ip, sizeof(ip), ipt_pknock_hash_rnd, 
			peer_hashsize);

	if (!list_empty(&rule->peer_head[hash])) {
		list_for_each_safe(pos, n, &rule->peer_head[hash]) {
			peer = list_entry(pos, struct peer, head);
			if (peer->ip == ip) return peer;
		}
	}
	return NULL;
}


/**
 * Reset the knock sequence status of the peer.
 * 
 * @peer
 */
static inline void 
reset_knock_status(struct peer *peer) 
{
	peer->id_port_knocked 	= 1;
	peer->status 		= ST_INIT;
}

/**
 * It creates a new peer matching status.
 *
 * @rule
 * @ip
 * @proto
 * @return: peer or NULL
 */
static inline struct peer * 
new_peer(u_int32_t ip, u_int8_t proto) 
{
	struct peer *peer = NULL;

	if ((peer = kmalloc(sizeof (*peer), GFP_ATOMIC)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in new_peer().\n");
		return NULL;
	}

	INIT_LIST_HEAD(&peer->head);
	peer->ip 	= ntohl(ip);
	peer->proto 	= proto;
	peer->timestamp = jiffies/HZ;
	peer->login_min = 0;
	reset_knock_status(peer);

	return peer;
}



/**
 * It adds a new peer matching status to the list.
 *
 * @peer
 * @rule
 */
static inline void 
add_peer(struct peer *peer, struct ipt_pknock_rule *rule)
{
	int hash = pknock_hash(&peer->ip, sizeof(peer->ip), 
			ipt_pknock_hash_rnd, peer_hashsize);

	list_add(&peer->head, &rule->peer_head[hash]);
}

/**
 * It removes a peer matching status.
 *
 * @peer
 */
static inline void 
remove_peer(struct peer *peer)
{
	list_del(&peer->head);
	if (peer) kfree(peer);
}

/**
 * @peer
 * @info
 * @port
 * @return: 1 success, 0 failure
 */
static inline int 
is_first_knock(const struct peer *peer, const struct ipt_pknock_info *info, 
		u_int16_t port)
{
	return (peer == NULL && info->port[0] == port) ? 1 : 0;
}

/**
 * @peer
 * @info
 * @port
 * @return: 1 success, 0 failure
 */
static inline int 
is_wrong_knock(const struct peer *peer, const struct ipt_pknock_info *info, 
		u_int16_t port)
{
	return peer && (info->port[peer->id_port_knocked-1] != port);
}

/**
 * @peer
 * @info
 * @return: 1 success, 0 failure
 */
static inline int 
is_last_knock(const struct peer *peer, const struct ipt_pknock_info *info)
{
	return peer && (peer->id_port_knocked-1 == info->count_ports);
}

/**
 * @peer
 * @return: 1 success, 0 failure
 */
static inline int 
is_allowed(const struct peer *peer) 
{
	return peer && (peer->status == ST_ALLOWED);
}


/**
 * Sends a message to user space through netlink sockets.
 * 
 * @info
 * @peer
 */
#if NETLINK_MSG
static void 
msg_to_userspace_nl(const struct ipt_pknock_info *info, const struct peer *peer, int multicast_group)
{
	struct cn_msg *m;
	struct ipt_pknock_nl_msg nlmsg;

	m = kmalloc(sizeof(*m) + sizeof(nlmsg), GFP_ATOMIC);
	if (m) {
		memset(m, 0, sizeof(*m) + sizeof(nlmsg));

		m->seq = 0;		
		m->len = sizeof(nlmsg);

		nlmsg.peer_ip = peer->ip;
		scnprintf(nlmsg.rule_name, info->rule_name_len + 1, 
				info->rule_name);

		memcpy(m + 1, (char *)&nlmsg, m->len);

		cn_netlink_send(m, multicast_group, GFP_ATOMIC);

		kfree(m);
	} 
}
#endif

/**
 * Transforms a sequence of characters to hexadecimal.
 *
 * @out: the hexadecimal result
 * @crypt: the original sequence
 * @size
 */
static void 
crypt_to_hex(char *out, char *crypt, int size) 
{
	int i;
	for (i=0; i < size; i++) {
		unsigned char c = crypt[i];
		*out++ = '0' + ((c&0xf0)>>4) + (c>=0xa0)*('a'-'9'-1);
		*out++ = '0' + (c&0x0f) + ((c&0x0f)>=0x0a)*('a'-'9'-1);
	}
}

/**
 * Checks that the payload has the hmac(secret+ipsrc+epoch_min).
 *
 * @secret
 * @secret_len
 * @ipsrc
 * @payload
 * @payload_len
 * @return: 1 success, 0 failure 
 */
static int 
has_secret(unsigned char *secret, int secret_len, u_int32_t ipsrc, 
		unsigned char *payload, int payload_len)
{
	struct scatterlist sg[2];
	char result[64];
	char *hexresult = NULL;
	int hexa_size;
	int ret = 0;
	int epoch_min;

	if (payload_len == 0)
		return 0;

	hexa_size = crypto.size * 2;

	/* + 1 cause we MUST add NULL in the payload */
	if (payload_len != hexa_size + 1)
		goto out;	

	hexresult = kmalloc(sizeof(char) * hexa_size, GFP_ATOMIC);
	if (hexresult == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in has_secret().\n");
		goto out;
	}

	epoch_min = get_epoch_minute();

	memset(result, 0, 64);
	memset(hexresult, 0, (sizeof(char) * hexa_size));

	sg_set_buf(&sg[0], &ipsrc, sizeof(ipsrc));
	sg_set_buf(&sg[1], &epoch_min, sizeof(epoch_min));

	crypto_hmac(crypto.tfm, secret, &secret_len, sg, 2, result);

	crypt_to_hex(hexresult, result, crypto.size);

	if (memcmp(hexresult, payload, hexa_size) != 0) { 
#if DEBUG
		printk(KERN_INFO MOD "secret match failed\n");
#endif
		goto out;
	}

	ret = 1;

out:	
	if (hexresult != NULL) kfree(hexresult);
	return ret;
}


/**
 * If the peer pass the security policy
 *
 * @peer
 * @info
 * @payload
 * @payload_len
 * @return: 1 if pass security, 0 otherwise
 */
static int 
pass_security(struct peer *peer, const struct ipt_pknock_info *info, 
		unsigned char *payload, int payload_len) 
{
	if (is_allowed(peer))
		return 1;

	/* The peer can't log more than once during the same minute. */
	if (has_logged_during_this_minute(peer)) {
		DEBUGP("BLOCKED", peer);			
		return 0;
	}
	/* Check for OPEN secret */
	if (!has_secret((unsigned char *)info->open_secret, 
				(int)info->open_secret_len, htonl(peer->ip), 
				payload, payload_len))
		return 0;

	return 1;
}

/**
 * It updates the peer matching status.
 *
 * @peer
 * @info
 * @rule
 * @transp
 * @return: 1 if allowed, 0 otherwise
 */
static int 
update_peer(struct peer *peer, const struct ipt_pknock_info *info, 
		struct ipt_pknock_rule *rule, 
		const struct transport_data *transp)
{
	unsigned long time;

	if (is_wrong_knock(peer, info, transp->port)) {
		DEBUGP("DIDN'T MATCH", peer);
		/* Peer must start the sequence from scratch. */
		if (info->option & IPT_PKNOCK_STRICT)
			reset_knock_status(peer);

		return 0;
	}

	/* If security is needed. */
	if (info->option & IPT_PKNOCK_OPENSECRET && 
			transp->proto == IPPROTO_UDP) {
		if (!pass_security(peer, info, transp->payload, 
					transp->payload_len)) {
			return 0;
		}
	}

	/* Just update the timer when there is a state change. */
	update_rule_timer(rule);

	peer->id_port_knocked++;

	if (is_last_knock(peer, info)) {
		peer->status = ST_ALLOWED;

		DEBUGP("ALLOWED", peer);
		
		if (nl_multicast_group > 0) {	
			msg_to_userspace_nl(info, peer, nl_multicast_group);
		}

		peer->login_min = get_epoch_minute(); 
		return 1;
	}

	/* Controls the max matching time between ports. */
	if (info->option & IPT_PKNOCK_TIME) {
		time = jiffies/HZ;
		
		if (is_time_exceeded(peer, info->max_time)) {
#if DEBUG
			DEBUGP("TIME EXCEEDED", peer);
			DEBUGP("DESTROYED", peer);
			printk(KERN_INFO MOD "max_time: %ld - time: %ld\n", 
					peer->timestamp + info->max_time, 
					time);
#endif
			remove_peer(peer);
			return 0;
		}
		peer->timestamp = time;		
	}
	DEBUGP("MATCHING", peer);
	peer->status = ST_MATCHING;
	return 0;
}


/**
 * Make the peer no more ALLOWED sending a payload with a special secret for 
 * closure.
 *
 * @peer
 * @info
 * @payload
 * @payload_len
 * @return: 1 if close knock, 0 otherwise
 */
static inline int 
is_close_knock(const struct peer *peer, const struct ipt_pknock_info *info, 
		unsigned char *payload, int payload_len) 
{
	/* Check for CLOSE secret. */
	if (has_secret((unsigned char *)info->close_secret, 
				(int)info->close_secret_len, htonl(peer->ip), 
				payload, payload_len)) {
		DEBUGP("RESET", peer);
		return 1;
	}
	return 0;
}


static int 
match(const struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	const void *matchinfo,
	int offset,
	int *hotdrop) 
{
	const struct ipt_pknock_info *info = matchinfo;
	struct ipt_pknock_rule *rule = NULL;
	struct peer *peer = NULL;
	struct iphdr *iph = skb->nh.iph;
	void *transp_h = (void *)iph + (iph->ihl * 4);	/* tranport header */
	int headers_len = 0;
	struct transport_data transp = {0, 0, 0, NULL};
	int ret = 0;	

	switch ((transp.proto = iph->protocol)) {
		case IPPROTO_TCP:
			transp.port = ntohs(((struct tcphdr *)transp_h)->dest);
			break;

		case IPPROTO_UDP:
			transp.port = ntohs(((struct udphdr *)transp_h)->dest);
			headers_len = (iph->ihl * 4) + sizeof(struct udphdr);
			break;

		default:
			printk(KERN_INFO MOD "IP payload protocol "
					"is neither tcp nor udp.\n");
			return 0;
	}

	spin_lock_bh(&list_lock);

	/* Searches a rule from the list depending on info structure options. */
	if ((rule = search_rule(info)) == NULL) {
		printk(KERN_INFO MOD "The rule %s doesn't exist.\n", 
				info->rule_name);
		goto out;
	}

	/* Gives the peer matching status added to rule depending on ip source. */
	peer = get_peer(rule, iph->saddr);

	if (info->option & IPT_PKNOCK_CHECKIP) {
		ret = is_allowed(peer);
		goto out;
	}

	transp.payload = (void *)iph + headers_len;
	transp.payload_len = skb->len - headers_len;

	/* Sets, updates, removes or checks the peer matching status. */
	if (info->option & IPT_PKNOCK_KNOCKPORT) {
		if ((ret = is_allowed(peer))) {
			if (info->option & IPT_PKNOCK_CLOSESECRET && 
					transp.proto == IPPROTO_UDP) {
				if (is_close_knock(peer, info, transp.payload, 
							transp.payload_len)) {
					reset_knock_status(peer);
					ret = 0;
				}
			}            
			goto out;
		}

		if (is_first_knock(peer, info, transp.port)) {
			peer = new_peer(iph->saddr, transp.proto);
			add_peer(peer, rule);
		}

		if (peer == NULL) goto out;

		update_peer(peer, info, rule, &transp);
	}

out:
#if DEBUG
	if (ret)
		DEBUGP("PASS OK", peer);
#endif		
	spin_unlock_bh(&list_lock);
	return ret;
}

#define RETURN_ERR(err) do { printk(KERN_ERR MOD err); return 0; } while (0)

static int 
checkentry(const char *tablename,
	const struct ipt_ip *ip,
	void *matchinfo,
	unsigned int matchinfosize,
	unsigned int hook_mask) 
{
	struct ipt_pknock_info *info = matchinfo;

	if (matchinfosize != IPT_ALIGN(sizeof (*info)))
		return 0;

	/* Singleton. */
	if (!rule_hashtable) {
		rule_hashtable = alloc_hashtable(rule_hashsize);
		get_random_bytes(&ipt_pknock_hash_rnd, 
				sizeof (ipt_pknock_hash_rnd));
	}

	if (!add_rule(info))
		RETURN_ERR("add_rule() error in checkentry() function.\n");

	if (!(info->option & IPT_PKNOCK_NAME))
		RETURN_ERR("You must specify --name option.\n");

	if ((info->option & IPT_PKNOCK_OPENSECRET) && (info->count_ports != 1))
		RETURN_ERR("--opensecret must have just one knock port\n");

	if (info->option & IPT_PKNOCK_KNOCKPORT) {
		if (info->option & IPT_PKNOCK_CHECKIP) {
			RETURN_ERR("Can't specify --knockports with "
					"--checkip.\n");
		}
		if ((info->option & IPT_PKNOCK_OPENSECRET) && 
				!(info->option & IPT_PKNOCK_CLOSESECRET)) {
			RETURN_ERR("--opensecret must go with "
					"--closesecret.\n");
		}
		if ((info->option & IPT_PKNOCK_CLOSESECRET) && 
				!(info->option & IPT_PKNOCK_OPENSECRET)) {
			RETURN_ERR("--closesecret must go with "
					"--opensecret.\n");
		}
	}

	if (info->option & IPT_PKNOCK_CHECKIP) {
		if (info->option & IPT_PKNOCK_KNOCKPORT)
			RETURN_ERR("Can't specify --checkip with "
					"--knockports.\n");
		if ((info->option & IPT_PKNOCK_OPENSECRET) || 
				(info->option & IPT_PKNOCK_CLOSESECRET))
			RETURN_ERR("Can't specify --opensecret and "
					"--closesecret with --checkip.\n");
		if (info->option & IPT_PKNOCK_TIME)
			RETURN_ERR("Can't specify --time with --checkip.\n");
	}

	if (info->option & IPT_PKNOCK_OPENSECRET) {
		if (info->open_secret_len == info->close_secret_len) {
			if (memcmp(info->open_secret, info->close_secret, 
						info->open_secret_len) == 0) {
				RETURN_ERR("opensecret & closesecret cannot "
						"be equal.\n");
			}
		}
	}

	return 1;
}

static void 
destroy(void *matchinfo, unsigned int matchinfosize)
{
	struct ipt_pknock_info *info = matchinfo;

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

static int __init ipt_pknock_init(void) 
{
	printk(KERN_INFO MOD "register.\n");

	if (request_module(crypto.algo) < 0) {
		printk(KERN_ERR MOD "request_module('%s') error.\n", 
				crypto.algo);
		return -1;
	}

	if ((crypto.tfm = crypto_alloc_tfm(crypto.algo, 0)) == NULL) {
		printk(KERN_ERR MOD "failed to load transform for %s\n",
				crypto.algo);
		return -1;
	}
	crypto.size = crypto_tfm_alg_digestsize(crypto.tfm);

	if (!(pde = proc_mkdir("ipt_pknock", proc_net))) {
		printk(KERN_ERR MOD "proc_mkdir() error in _init().\n");
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

	if (crypto.tfm != NULL) crypto_free_tfm(crypto.tfm);	
}

module_init(ipt_pknock_init);
module_exit(ipt_pknock_fini);
