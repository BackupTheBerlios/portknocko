/*
 *	$Id: list_wq2.c,v 1.1.1.1 2004/11/05 16:15:17 brugge Exp $
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/wait.h>
#include <linux/list.h> /* manejo de listas 2linkeadas */

#include <linux/string.h> 

#include "chardev.h"
#include "list_wq2.h"
#include "utils.h"

int elem_max = 50;

atomic_t _elem_count = ATOMIC_INIT(0);

LIST_HEAD(elem_head);
DECLARE_WAIT_QUEUE_HEAD(readq);
DECLARE_WAIT_QUEUE_HEAD(writeq);

DECLARE_MUTEX(elem_base_lock);	/* MUTEX para acceso/modif. de cabeza de lista */

static __inline__ int mi_LOCK(struct semaphore *sem)
 { return !(down_interruptible(sem));}
static __inline__ void mi_UNLOCK(struct semaphore *sem)
 { return up(sem);}
/*
 * Devuelve un elemento con el contenido de str en e->str.
 */
struct elem_t *elem_new(__u32 ipaddr) {
	struct elem_t* e;
	int size = sizeof(*e);
	e=kmalloc(size, GFP_KERNEL);
	if (e!=NULL) {
		INIT_LIST_HEAD(&e->list);
		e->ip_addr = htonl(ipaddr);
	}
	return e;
}
void elem_destroy(struct elem_t *e) {
	kfree(e);
}
/*
 * Adiciona un elemento a la cola de la lista
 * el caller DEBE lockear.
 */
static void __elem_add(struct elem_t *e) {
	list_add_tail(&e->list, &elem_head);
	atomic_inc(&_elem_count);
}
/* 
 * Extrae un elemento, el caller DEBE lockear. 
 */
static void __elem_pull(struct elem_t *e) {
	atomic_dec(&_elem_count);
	list_del(&e->list); 
}
/* 
 * Obtiene un elemento sin sacarlo. 
 */
struct elem_t *__elem_peek(void) {
	if (list_empty(&elem_head))
		return NULL;
	return list_entry(elem_head.next, struct elem_t, list);
}
/* 
 * Agrega un elemento, ahora _si'_ puede dormir
 * por "max".
 */
int elem_add(struct elem_t *e) {
/*L* significa area "LOCKeada" */

retry:
	if (!mi_LOCK(&elem_base_lock)) 
		return -ERESTARTSYS;

/*L*/	if (elem_count() >= elem_max) {
/*L*/
/*L*/		mi_UNLOCK(&elem_base_lock);

		interruptible_sleep_on(&writeq);
		if (signal_pending(current))
			return -ERESTARTSYS;

		goto retry;
	}

/*L*/	__elem_add(e);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
/*L*/	MOD_INC_USE_COUNT;
#endif
	mi_UNLOCK(&elem_base_lock);

	wake_up(&readq);
	return 0;
}
struct elem_t *elem_pull(void) {
	struct elem_t *e;

retry:
	if (!mi_LOCK(&elem_base_lock)) return NULL;

/*L*/	e=__elem_peek();
/*L*/
/*L*/	if (e==NULL) {

		mi_UNLOCK(&elem_base_lock);

		interruptible_sleep_on(&readq);
		if (signal_pending(current)) {
			return NULL;
		}
		goto retry;
	}

/*L*/	__elem_pull(e);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
/*L*/	MOD_DEC_USE_COUNT;
#endif
/*L*/
	mi_UNLOCK(&elem_base_lock);

	wake_up(&writeq);
	return e;
}
int elem_count(void) {
	return atomic_read(&_elem_count);
}
/*
 * Busca una ip_addr en la lista.
 */
int elem_list_ip_cmp(__u32 ipaddr) {
	struct elem_t *e;
	struct list_head *p;
	/*
	 * Si la lista está vaciá devuelve -1.
	 */
	if (list_empty(&elem_head)) 
		return -1;
	PDEBUG("iph->saddr: %08x\n", ipaddr);	
	/*
	 * Si encuentra ip_addr en la lista devuelve 0.
	 */	
	for (p = &elem_head, e = (elem_t *)p->next; e != (elem_t *)p; 
			e = (elem_t *)e->list.next) {
		PDEBUG("ip_addr: %08x\n", e->ip_addr);
		if (e->ip_addr == ipaddr) return 0;	
	}
	return -2;
}
/* Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 8
 * End:
 */
/*
 *	$Log: list_wq2.c,v $
 *	Revision 1.1.1.1  2004/11/05 16:15:17  brugge
 *	
 *	
 *	Revision 1.7  2004/11/05 15:35:33  brugge
 *	Se cambiaron los tipos de ipaddr, de unsigned long a __u32.
 *	
 *	Revision 1.6  2004/11/05 15:29:39  brugge
 *	Se cambiaron los tipos de ipaddr a __u32.
 *	
 *	Revision 1.5  2004/11/05 15:20:58  brugge
 *	Se modificó la función elem_new() cuando hacía e->ip_addr = ip_addr a
 *	e->ip_addr = htonl(ip_addr).
 *	
 *	Revision 1.4  2004/11/05 14:50:25  brugge
 *	Se cambiaron los valores que retornaba la fc elem_list_ip_cmp().
 *	
 *	Revision 1.3  2004/11/04 15:48:10  brugge
 *	Se corrigió la implementación de la función elem_list_ip_cmp().
 *	
 *	Revision 1.2  2004/11/04 14:37:50  brugge
 *	Corrección menor.
 *	
 *	Revision 1.1.1.1  2004/11/04 13:50:13  brugge
 *	Versión incial.
 *	
 */
