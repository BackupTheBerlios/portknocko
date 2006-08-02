/*
 * Shared library add-on to iptables to add port knocking matching support.
 *
 * (C) 2006 J. Federico Hernandez <fede.hernandez@gmail.com>
 *
 * $Id$
 *
 * This program is released under the terms of GNU GPL.
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <iptables.h>
//#include <linux/netfilter_ipv4/ipt_pknock.h>
#include "../kernel/ipt_pknock.h"

static struct option opts[] = {
        { .name = "setip",	.has_arg = 0,	.flag = 0,	.val = 's' },
	{ .name = "checkip", 	.has_arg = 0, 	.flag = 0,	.val = 'c' },
	{ .name = "chkip", 	.has_arg = 0, 	.flag = 0,	.val = 'c' }, /* synonym */
	{ .name = "dports", 	.has_arg = 1,	.flag = 0,	.val = 'd' },
	{ .name = "destination-ports", .has_arg = 1, .flag = 0,	.val = 'd' }, /* synonym */
	{ .name = "t",		.has_arg = 1, 	.flag = 0, 	.val = 't' },
	{ .name = "time",	.has_arg = 1, 	.flag = 0,	.val = 't' }, /* synonym */
	{ .name = "name", 	.has_arg = 1, 	.flag = 0, 	.val = 'n' },
	{ .name = 0 }
};

static void help(void) {
	printf("Port Knocking match v%s options:\n"
		" --setip		Adds a source ip address to list, it always matches.\n"
		" --checkip		Matches if the source ip address is in the list.\n"
		" --chkip\n"
		" --destination-ports port[,port,port,...]\n"
		" --dports ...		Matches destination port(s).\n"
		" --time seconds\n"
		" --t ...		Time between port match.\n"
		" --name rule_name	Rule name.\n", IPTABLES_VERSION);
}

/*
 * Se llama al cargarse el módulo. Inicializa el match (se setean
 * valores por defecto y el cacheo de netfilter.
 */
static void init(struct ipt_entry_match *m, unsigned int *nfcache) {
	*nfcache |= NFC_UNKNOWN;
}

/*
 * parse_ports():
 *
 * Parsea ports por comas (ej. de ports: "4000,1000,2000"), los 
 * convierte a entero y los devuelve en port_buf.
 *
 * @param const char *ports	number of ports
 * @param u_int16_t *port_buf
 * @param u_int8_t *count	count ports
 * @return			0 success, > 0 otherwise
 */
static int parse_ports(const char *ports, u_int16_t *port_buf, u_int8_t *count) {
	char *token=NULL, *str=NULL;
	const char *delim = ",";
	int i;
	
	if (ports == NULL) return 1;

	if ((str = strdup(ports)) == NULL) return 2;

	for (i=0, token = strtok(str, delim); token != NULL && i < IPT_PKNOCK_MAX_PORTS; 
	token = strtok(NULL, delim), i++, port_buf++) {
		if (string_to_number(token, 0, 65535, (unsigned int *)port_buf) == -1) {
			if (str) free(str);
			return 3;
		}
#if DEBUG
		printf("port[%d]: %d\n", i, *port_buf);
#endif
	}
	*count = i;

	if (str) free(str);
	return 0;
}

#define EXIT_ERR_REPORT(error_val) do { 						\
	switch (error_val) {								\
	case 1:										\
		fprintf(stderr, "%s port[,port,port,...]\n", argv[0]); break;		\
	case 2:										\
		fprintf(stderr, "There isn't enough memory - strdup().\n"); break; 	\
	case 3:										\
		fprintf(stderr, "Port number invalid.\n"); break;			\
	}										\
	exit(EXIT_FAILURE);								\
} while (0)										\

/*
 * parse()
 *
 * Parsea la línea de comandos. Devuelve true si encuentra una opción.
 * Es llamada cada vez que se encuentra un argumento.
 *
 * @param integer c - código del argumento
 * @param struct ipt_entry_match *match - contiene los argumentos, es compartida con el espacio de kernel.
 *
 * @return integer - 1 if option is found, 0 otherwise
 */
static int parse(int c, char **argv, int invert, unsigned int *flags, 
		const struct ipt_entry *entry, 
		unsigned int *nfcache, 
		struct ipt_entry_match **match) {
	struct ipt_pknock_info *info = (struct ipt_pknock_info *) (*match)->data;
	int ret=0;

/*** VERIFICAR en cada opción el inverso (!). */
	
	switch (c) {
	case 's': /* --setip */
		if (*flags & IPT_PKNOCK_SETIP)
			exit_error(PARAMETER_PROBLEM, MOD "Can't use --setip twice.\n"); 

		*flags |= IPT_PKNOCK_SETIP;
		info->option |= IPT_PKNOCK_SETIP;
		break;
		
	case 'c': /* --checkip */
		if (*flags & IPT_PKNOCK_CHKIP)
			exit_error(PARAMETER_PROBLEM, MOD "Can't use --checkip twice.\n");

		*flags |= IPT_PKNOCK_CHKIP;
		info->option |= IPT_PKNOCK_CHKIP;
		break;
		
	case 'd': /* --destination-ports */
		if (*flags & IPT_PKNOCK_DPORT)
			exit_error(PARAMETER_PROBLEM, MOD "Cant't use --dport twice.\n");
		
		if ((ret = parse_ports(optarg, info->port, &(info->count_ports))) != 0) 
			EXIT_ERR_REPORT(ret);
#if DEBUG
		printf("count_ports: %d\n", info->count_ports);
#endif
		*flags |= IPT_PKNOCK_DPORT;
		info->option |= IPT_PKNOCK_DPORT;
		break;
		
	case 't': /* --time */
		if (*flags & IPT_PKNOCK_TIME)
			exit_error(PARAMETER_PROBLEM, MOD "Cant't use --time twice.\n");
		
		info->max_time = atoi(optarg);	
		
		*flags |= IPT_PKNOCK_TIME;
		info->option |= IPT_PKNOCK_TIME;
		break;
		
	case 'n': /* --name */
		if (*flags & IPT_PKNOCK_NAME)
			exit_error(PARAMETER_PROBLEM, MOD "Can't use --name twice.\n");
	
		strncpy(info->rule_name, optarg, IPT_PKNOCK_MAX_BUF_LEN);		
		info->rule_name_len = strlen(info->rule_name);
#if DEBUG
		printf("info->rule_name: %s\n", info->rule_name);
#endif
		*flags |= IPT_PKNOCK_NAME;
		info->option |= IPT_PKNOCK_NAME;
		break;
		
	default:
		return 0;
	}
	return 1;
}

/*
 * Esta función da una última oportunidad de verificar las reglas. Es llamada después
 * del parseo de los argumentos.
 */
static void final_check(unsigned int flags) { 
	if (!flags)
		exit_error(PARAMETER_PROBLEM, MOD "you must specify an option.\n");
}

/*
 * Imprime información sobre la regla. Es llamada por "iptables -L".
 */
static void print(const struct ipt_ip *ip, const struct ipt_entry_match *match, int numeric) {
	const struct ipt_pknock_info *info = (const struct ipt_pknock_info *)match->data;
	int i;
	
	printf("pknock ");
	if (info->option & IPT_PKNOCK_SETIP) printf("setip ");
	if (info->option & IPT_PKNOCK_CHKIP) printf("chkip ");
	if (info->option & IPT_PKNOCK_DPORT) {
		printf("dports ");
		for (i=0; i<info->count_ports; i++)
			printf("%s%d", i ? "," : "", info->port[i]);
		printf(" ");
	}
	if (info->option & IPT_PKNOCK_TIME) printf("time %ld ", info->max_time);
	if (info->option & IPT_PKNOCK_NAME) printf("name %s ", info->rule_name);
}

/*
 * Esta función muestra por pantalla todos los argumentos de una regla determinada. Estos 
 * argumentos están almacenados en la estructura ipt_entry_match que identifica a una regla.
 * Es llamada cuando se usa "iptables-save".
 */
static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match) {
	const struct ipt_pknock_info *info = (const struct ipt_pknock_info *)match->data;
	int i;
	
	if (info->option & IPT_PKNOCK_SETIP) printf("--setip ");
	if (info->option & IPT_PKNOCK_CHKIP) printf("--chkip ");
	if (info->option & IPT_PKNOCK_DPORT) {
		printf("--dports ");
		for (i=0; i<info->count_ports; i++)
			printf("%s%d", i ? "," : "", info->port[i]);
		printf(" ");
	}
	if (info->option & IPT_PKNOCK_TIME) printf("--time %ld ", info->max_time);
	if (info->option & IPT_PKNOCK_NAME) printf("--name %s ", info->rule_name);
}


static struct iptables_match pknock = {
	.name 		= "pknock",
	.version 	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(sizeof (struct ipt_pknock_info)),
	.userspacesize	= IPT_ALIGN(sizeof (struct ipt_pknock_info)),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};


void _init(void) {
	register_match(&pknock);
}

