/*
 * $Id: main.c,v 1.2 2006/05/08 14:29:58 brugge Exp $
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>

#include "linux_list.h"
#include "list.h"
#include "parse_port.h"

#define SIZE_BUF 80
#define IPT_MAX_PORTS 15

#define ERR_GO(err, go) do { perror(err); goto go; } while (0)

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]


void *udp_match(void *arg);


u_int16_t port_match[IPT_MAX_PORTS];
u_int8_t  port_match_count;


/*
 * list port[port,port,...]
 * list "5000,2000,3000"
 */

int main(int argc, char **argv) {
	int i;
	pthread_t tid[IPT_MAX_PORTS];

	if (argc != 2) {
		printf("Uso:\n%s port[port,port,...]\n", argv[0]);
		return 1;
	}
	
	memset(port_match, 0, sizeof port_match);
	memset(tid, 0, sizeof tid);
	
	parse_ports(argv[1], port_match, &port_match_count);


	for (i=0; i<port_match_count; i++)
		pthread_create(&tid[i], NULL, udp_match, (void *)&port_match[i]);
		
	for (i=0; i<port_match_count; i++)
		pthread_join(tid[i], NULL);
	
#if 0
	struct match_info *n=NULL;
	struct match_info m = { {NULL, NULL}, 2, 0, ST_BLOCKED, 0, 1 };

	/* 
	 * Ejemplo de uso de la lista. 
	 */
	n = node_new(1);
	node_add(n);
	sleep(1);
	n = node_new(2);
	node_add(n);
	sleep(1);
	n = node_new(3);
	node_add(n);
	
	list_print();	
	
	node_find(&m);	

	n = node_pull();
	printf("node_pulled: %d\n", n->ip);
	node_destroy(n);

	list_print();
#endif

	return 0;
}


void *udp_match(void *arg) {
	u_int16_t port = *(u_int16_t *)arg;
	struct sockaddr_in addr;
	struct match_info *nn=NULL, *nf=NULL;
	char buf[SIZE_BUF];
	int sd;
	int addr_len=0;
	int i;
	
	memset(buf, 0, sizeof buf);

	addr.sin_family 	= AF_INET;
	addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	addr.sin_port 		= htons(port);

	addr_len = sizeof addr;

	if ( (sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		ERR_GO("socket()\n", err);
	
	if (bind(sd, (struct sockaddr *)&addr, sizeof addr) == -1)
		ERR_GO("bind()\n", err);
	
	while (1) {
		recvfrom(sd, buf, sizeof buf, 0, (struct sockaddr *)&addr, &addr_len);

		printf("\nMessage: %s\n", buf);
/***/
		/*
		 * Creo un nodo nuevo con la dir ip del paquete que llega.
		 */
		nn = node_new(addr.sin_addr.s_addr, port_match_count);
		
		/* 
		 * Si el nodo no está en la lista lo agrego. 
		 */
		if ( (nf = node_find(nn)) == NULL) {
			node_add(nn);
			continue;
		}
		node_destroy(nn);

		/* 
		 * Si está, verifico la coincidencias entre puertos y el id del puerto
		 * que debería golpear.
		 */
		for (i=0; i<port_match_count; i++) {
			if (port_match[i] == port) {
				if (nf->port_count == nf->id_port_knocked) {
					nf->conn_status = ST_ALLOWED;
					break;
				}				
				
				if (nf->id_port_knocked == i) {
					nf->conn_status = ST_MATCHED;
					nf->id_port_knocked++;
				} else {
					printf("Golpeteo de puertos incorrecto o se golpeó más de una vez un puerto.\n"
						"Se esparaba un golpe en el puerto: %d\n", 
						port_match[i]);
				}	
			}
		}		
		unsigned long ip = ntohl(nf->ip);
		printf("node found:\n"
			"nf->ip: %u.%u.%u.%u\nnf->ip_port_knocked: %d\n"
			"nf->port_count: %d\nnf->conn_status: %s\n"
			"remote port: %d\n",
			NIPQUAD(ip), nf->id_port_knocked, nf->port_count, status(nf->conn_status), 
			addr.sin_port);

/***/
		if (strncmp("PING_UDP", buf, 4) == 0) {
			sendto(sd, "PONG_UDP", 8, 0,(struct sockaddr *)&addr, addr_len);
			//break;
		}
	}

err:
	close(sd);
	return NULL;
}

/*
 * $Log: main.c,v $
 * Revision 1.2  2006/05/08 14:29:58  brugge
 * Corrección menor.
 *
 * Revision 1.1  2006/04/25 00:18:32  brugge
 * Versión inicial.
 *
 */
