/*
 *	$Id: list_wq2.h,v 1.1.1.1 2004/11/05 16:15:17 brugge Exp $
 */
#ifndef _LIST_WQ2_H_
#define _LIST_WQ2_H_
int 	my_procfs_init(void);
void 	my_procfs_done(void);
int 	my_sleep(int ticks);

typedef struct elem_t {
	struct list_head list;
	__u32 ip_addr;
} elem_t;

struct 	elem_t *elem_new(__u32 ipaddr);
void 	elem_destroy(struct elem_t *e);
int 	elem_add(struct elem_t *e);
struct 	elem_t *elem_pull(void);
int 	elem_count(void);
int 	elem_list_ip_cmp(__u32 ipaddr);
#endif
/*
 * 	$Log: list_wq2.h,v $
 * 	Revision 1.1.1.1  2004/11/05 16:15:17  brugge
 * 	
 * 	
 * 	Revision 1.4  2004/11/05 15:29:39  brugge
 * 	Se cambiaron los tipos de ipaddr a __u32.
 * 	
 * 	Revision 1.3  2004/11/05 14:52:13  brugge
 * 	Corrección menor.
 * 	
 * 	Revision 1.2  2004/11/04 15:49:29  brugge
 * 	Se agregó un alias a la estructura elem_t (typedef struct elem_t elem_t).
 * 	
 * 	Revision 1.1.1.1  2004/11/04 13:50:13  brugge
 * 	Versión incial.
 * 	
 */
