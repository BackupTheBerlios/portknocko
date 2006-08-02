/*
 *	$Id: list.h,v 1.2 2006/04/27 22:14:04 brugge Exp $
 */
#ifndef _LIST_H_
#define _LIST_H_

#include <time.h>
#include <sys/types.h>

#include "linux_list.h"

enum status {ST_BLOCKED=1, ST_MATCHED, ST_ALLOWED};

struct match_info {
	struct list_head list;
	u_int32_t 	ip;
	u_int32_t 	id_port_knocked;
	u_int32_t 	port_count;
	enum status 	conn_status;
	unsigned long 	timestamp;
};
			

struct match_info *node_new(u_int32_t ip, u_int32_t port_count);
void node_destroy(struct match_info *n);
void node_add(struct match_info *n);
struct match_info *node_pull(void);
int node_count(void);
struct match_info * node_find(struct match_info *n);
void list_print(void);


static inline const char * status(enum status st) {
	const char *p=NULL;

	switch (st) {
	case ST_BLOCKED:
		p="BLOCKED"; break;
	case ST_MATCHED:
		p="MATCHED"; break;
	case ST_ALLOWED:
		p="ALLOWED"; break;
	default:
		p="NOT DEFINED"; break;
	}

	return p;
}

#endif

/*
 * $Log: list.h,v $
 * Revision 1.2  2006/04/27 22:14:04  brugge
 * Se eliminó el campo ref_count de la estructura.
 *
 * Revision 1.1  2006/04/25 00:18:05  brugge
 * Versión inicial.
 *
 */
