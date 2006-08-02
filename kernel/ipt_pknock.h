/*
 * Kernel module to implement port knocking matching support.
 * 
 * (C) 2006 J. Federico Hernandez <fede.hernandez@gmail.com>
 *
 * $Id: ipt_pknock.h,v 1.24 2006/06/02 21:04:03 brugge Exp $
 *
 * This program is released under the terms of GNU GPL.
 */
#ifndef _IPT_PKNOCK_H
#define _IPT_PKNOCK_H

#define MOD "ipt_pknock: "

#define IPT_PKNOCK_SETIP 0x0001
#define IPT_PKNOCK_CHKIP 0x0002
#define IPT_PKNOCK_DPORT 0x0004
#define IPT_PKNOCK_TIME  0x0008
#define IPT_PKNOCK_NAME  0x0010


#define IPT_PKNOCK_MAX_PORTS 	15
#define IPT_PKNOCK_MAX_BUF_LEN 	256

#define DEBUG 1

struct ipt_pknock_info {
	char		rule_name[IPT_PKNOCK_MAX_BUF_LEN]; /* rule name */
	int		rule_name_len;
	u_int8_t 	count_ports;			/* number of ports */
	u_int16_t 	port[IPT_PKNOCK_MAX_PORTS];	/* port[,port,port,...] */
	unsigned long 	max_time;			/* max matching time between ports */
	u_int8_t 	option;	/* --setip, --checkip, --dport, --time */
};

enum status {ST_INIT=1, ST_MATCHING, ST_ALLOWED};

#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/spinlock.h>

struct peer_status {
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
	unsigned int		ref_count;
	struct timer_list 	timer;		/* garbage collector timer */
	struct list_head 	peer_status_head;
	struct proc_dir_entry  	*status_proc;
	unsigned long		max_time;	/* max matching time between ports */
};

#endif /* __KERNEL__ */
#endif /* _IPT_PKNOCK_H */

/*
 * $Log: ipt_pknock.h,v $
 * Revision 1.24  2006/06/02 21:04:03  brugge
 * Se elimno la opcion --rmip o --removeip y su tratamiento en las distintas
 * funciones.
 *
 * Revision 1.23  2006/06/02 04:25:39  brugge
 * Correciones menores.
 *
 * Revision 1.22  2006/05/24 06:21:52  brugge
 * Se cambiaron los nombres de los estados de enum status.
 * Se agregó (temporalmente) el campo max_time a la estructura ipt_pknock_rule.
 *
 * Revision 1.21  2006/05/23 16:01:26  brugge
 * *** empty log message ***
 *
 * Revision 1.20  2006/05/22 14:34:55  brugge
 * Se agrego el campo proc_status, del tipo proc_dir_entry, en la estructura
 * ipt_pknock_rule.
 *
 * Revision 1.19  2006/05/18 22:13:03  brugge
 * Se cambió el nombre del estado ST_DELETED a ST_DELETE.
 *
 * Revision 1.18  2006/05/18 21:25:43  brugge
 * Se agregó el campo timer a la estructura ipt_pknock_rule.
 *
 * Revision 1.17  2006/05/16 21:33:47  brugge
 * Se eliminó el campo option de la estructura ipt_pknock_rule.
 *
 * Revision 1.16  2006/05/15 21:30:26  brugge
 * Se cambió el nombre del campo time de la estructura ipt_pknock_info a
 * max_time.
 *
 * Revision 1.15  2006/05/14 23:30:38  brugge
 * Se agregó el campo rule_name_len en la estructura ipt_pknock_info.
 *
 * Revision 1.14  2006/05/11 13:29:49  brugge
 * Se renombraron las opciones del módulo.
 *
 * Revision 1.13  2006/05/08 20:41:36  brugge
 * Se corrigieron los nombres de los valores de status.
 * Se eliminaron los campos port y count port de la estructura
 * ipt_pknock_rule.
 *
 * Revision 1.12  2006/05/08 14:29:34  brugge
 * Se cambió el nombre de la estructura peer_conn_status por el de
 * peer_status.
 * Se eliminó el campo time de la estructura ipt_pknock_rule y se cambió
 * el nombre del campo peer_status_head por el de peer_status_list_head.
 *
 * Revision 1.11  2006/05/05 21:46:23  brugge
 * Se agregaron dos campos a la estructura peer_conn_status: proto y
 * id_port_knocked_rm.
 *
 * Revision 1.10  2006/05/04 20:24:17  brugge
 * Se eliminó el campo count_ports de la estructura peer_conn_status y el
 * campo peer_status de la estructura ipt_pknock_rule. A esta última se le
 * agregó el campo peer_status_head.
 *
 * Revision 1.9  2006/05/04 00:15:37  brugge
 * Se cambió el valor de IPT_PKNOCK_MAX_BUF_LEN.
 *
 * Revision 1.8  2006/04/28 22:26:56  brugge
 * Correcciones menores.
 *
 * Revision 1.7  2006/04/28 21:52:21  brugge
 * Se agregó la opción IPT_PKNOCK_NAME.
 * Se cambiaron los campos rule_name de dos estructuras, de unsigned char a
 * char.
 *
 * Revision 1.6  2006/04/28 20:27:23  brugge
 * Se modificó la estructura ipt_pknock_info, eliminando el campo src y
 * agregando el campo rule_name.
 * Se agregó la estructura peer_conn_status y la estructura ipt_pknock_rule.
 *
 * Revision 1.5  2006/04/17 03:37:50  brugge
 * Correcciones menores.
 *
 * Revision 1.4  2006/04/11 00:44:09  brugge
 * Versión inicial.
 *
 * Revision 1.3  2006/04/11 00:13:11  brugge
 * Corrección menor.
 *
 * Revision 1.2  2006/04/07 22:13:37  brugge
 * Se agregaron las macros correspondientes a las opciones.
 *
 * Revision 1.1.1.1  2006/04/07 13:29:53  brugge
 * Versión inicial.
 *
 */
