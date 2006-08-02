/*
 *	$Id: list.c,v 1.2 2006/04/27 22:14:04 brugge Exp $
 */
#include <stdio.h>
#include <stddef.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#include "linux_list.h"
#include "list.h"


LIST_HEAD(head);

/*
 * Crea un nuevo nodo y lo devuelve. Si no lo puede crear, devuelve NULL.
 */
struct match_info *node_new(u_int32_t ip, u_int32_t port_count) {
	struct match_info *n=NULL;

	/* MALLOC después será KMALLOC */
	if ( (n = (struct match_info *)malloc(sizeof (*n))) != NULL) {
		n->ip 		= ntohl(ip);
		n->id_port_knocked = 0;
		n->port_count	= port_count;
		n->conn_status 	= ST_BLOCKED;
		n->timestamp	= time(NULL);
	}	

	return n;
}

/*
 * Libera la memoria asignada al nodo n.
 */
void node_destroy(struct match_info *n) {

	/* FREE luego será KFREE */
	if (n) free(n);
}

/*
 * Adhiere un nodo en la cola de la lista.
 */
void node_add(struct match_info *n) {
	list_add_tail(&n->list, &head);
}

/*
 * Extrae y devuelve el primer nodo de la lista.
 * El que llama a esta función debe hacer luego un node_destroy() del
 * nodo que devuelve.
 */
struct match_info *node_pull(void) {
	struct match_info *n=NULL;

	if ( (n = list_entry(head.next, struct match_info, list)) != NULL)
		list_del(&n->list);

	return n;
}

int node_count(void) {
	return 0;
}

/*
 * Busca un nodo en la lista, si lo encuentra devuelve el nodo, sino NULL.
 */
struct match_info * node_find(struct match_info *n) {
	struct list_head *pos=NULL;
	struct match_info *m=NULL;

	list_for_each(pos, &head) {
		m = list_entry(pos, struct match_info, list);
		if (m->ip == n->ip) {
			printf("node_found: %d\n", m->ip);
			return m;
		}
	}

	return NULL;
}

/*
 * Imprime la lista.
 */
void list_print(void) {
	struct list_head *pos=NULL;
	struct match_info *n=NULL;

	list_for_each(pos, &head) {
		n = list_entry(pos, struct match_info, list);
		printf("node->ip: %d\n", n->ip);
		printf("node->t: %ld\n", n->timestamp);
	}
}

/*
 * $Log: list.c,v $
 * Revision 1.2  2006/04/27 22:14:04  brugge
 * Se eliminó el campo ref_count de la estructura.
 *
 * Revision 1.1  2006/04/25 00:18:05  brugge
 * Versión inicial.
 *
 */
