/*
 * Kernel module to implement port knocking matching support.
 * 
 * (C) 2006 J. Federico Hernandez <fede.hernandez@gmail.com>
 * (C) 2006 Luis Floreani <luis.floreani@gmail.com>
 *
 * $Id$
 *
 * This program is released under the terms of GNU GPL.
 */
#ifndef _IPT_PKNOCK_H
#define _IPT_PKNOCK_H

#define MOD "ipt_pknock: "

#define IPT_PKNOCK_KNOCKPORT 	0x0001
#define IPT_PKNOCK_TIME  	0x0002
#define IPT_PKNOCK_NAME  	0x0004
#define IPT_PKNOCK_SECURE  	0x0008
#define IPT_PKNOCK_STRICT  	0x0010


#define IPT_PKNOCK_MAX_PORTS 		15
#define IPT_PKNOCK_MAX_BUF_LEN 		8
#define IPT_PKNOCK_MAX_PASSWD_LEN 	32

#define DEBUG 1
#define NETLINK_MSG 1

struct ipt_pknock_info {
	char		rule_name[IPT_PKNOCK_MAX_BUF_LEN]; /* rule name */
	int		rule_name_len;
	char		password[IPT_PKNOCK_MAX_PASSWD_LEN]; /* password */
	int		password_len;
	u_int8_t 	count_ports;			/* number of ports */
	u_int16_t 	port[IPT_PKNOCK_MAX_PORTS];	/* port[,port,port,...] */
	unsigned long 	max_time;			/* max matching time between ports */
	u_int8_t 	option;				/* --time, --knock-port, ... */
};

struct ipt_pknock_nl_msg {
	char			rule_name[IPT_PKNOCK_MAX_BUF_LEN];
	u_int32_t 		peer_ip;
};


enum status {ST_INIT=1, ST_MATCHING, ST_ALLOWED};

#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/spinlock.h>

struct peer {
	struct list_head head;
	u_int32_t 	ip;
	u_int8_t	proto;
	u_int32_t 	id_port_knocked;
	enum status 	status;
	unsigned long 	timestamp;
};

#include <linux/proc_fs.h>

struct ipt_pknock_rule {
	struct list_head 	head;
	char			rule_name[IPT_PKNOCK_MAX_BUF_LEN];
	int			rule_name_len;
	unsigned int		ref_count;
	struct timer_list 	timer;		/* garbage collector timer */
	struct list_head 	*peer_head;
	struct proc_dir_entry  	*status_proc;
	unsigned long		max_time;	/* max matching time between ports */
};

#endif /* __KERNEL__ */
#endif /* _IPT_PKNOCK_H */

