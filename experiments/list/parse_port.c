/*
 * $Id: parse_port.c,v 1.1 2006/04/25 00:18:49 brugge Exp $
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define IPT_MAX_PORTS 15

#define DEBUG 1

/*
 *  Funciones definidas en iptables.h
 */
static int string_to_number_ll(const char *s, unsigned long long min, unsigned long long max, unsigned long long *ret) {
	unsigned long long number;
	char *end;

	/* Handle hex, octal, etc. */
	errno = 0;
	number = strtoull(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (errno != ERANGE && min <= number && (!max || number <= max)) {
			*ret = number;
			return 0;
		}
	}
	return -1;
}

static int string_to_number_l(const char *s, unsigned long min, unsigned long max, unsigned long *ret) {
	int result;
	unsigned long long number;

	result = string_to_number_ll(s, min, max, &number);
	*ret = (unsigned long)number;

	return result;
}

static int string_to_number(const char *s, unsigned int min, unsigned int max, unsigned int *ret) {
	int result;
	unsigned long number;

	result = string_to_number_l(s, min, max, &number);
	*ret = (unsigned int)number;

	return result;
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
int parse_ports(const char *ports, u_int16_t *port_buf, u_int8_t *count) {
	char *token=NULL, *str=NULL;
	const char *delim = ",";
	int i;
	
	if (ports == NULL) return 1;

	if ( (str = strdup(ports)) == NULL) return 2;

	for (i=0, token = strtok(str, delim); 
		token != NULL && i < IPT_MAX_PORTS; 
			token = strtok(NULL, delim), i++, port_buf++) {
		string_to_number(token, 0, 65535, (unsigned int *)port_buf);
#if DEBUG
		printf("port: %d\n", *port_buf);
#endif
	}
	*count = i;

	free(str);
	return 0;
}

/*
 * $Log: parse_port.c,v $
 * Revision 1.1  2006/04/25 00:18:49  brugge
 * Versión estable.
 *
 */
