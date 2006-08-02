/*
 * $Id: parse_port.c,v 1.1 2006/04/17 13:27:35 brugge Exp $
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
int string_to_number_ll(const char *s, unsigned long long min, unsigned long long max, unsigned long long *ret);
int string_to_number_l(const char *s, unsigned long min, unsigned long max, unsigned long *ret);
int string_to_number(const char *s, unsigned int min, unsigned int max, unsigned int *ret);

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


int main(int argc, char **argv) {
	int ret=0;
	int i;
	u_int16_t port_buf[IPT_MAX_PORTS];
	u_int8_t count_ports=0;

	memset(port_buf, 0, sizeof port_buf);

	ret = parse_ports(argv[1], port_buf, &count_ports);

	switch (ret) {
	case 1:
		fprintf(stderr, "%s port[,port,port,...]\n", argv[0]);
		return ret;
	case 2:
		fprintf(stderr, "No hay suficiente memoria (strdup())\n.");
		return ret;
	}

	for (i=0; i<IPT_MAX_PORTS; i++)
		printf("port[%d]: %d\n", i, port_buf[i]);
	printf("count: %d\n", count_ports);
	
	return ret;
}

 
int string_to_number_ll(const char *s, unsigned long long min, unsigned long long max, unsigned long long *ret) {
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

int string_to_number_l(const char *s, unsigned long min, unsigned long max, unsigned long *ret) {
	int result;
	unsigned long long number;

	result = string_to_number_ll(s, min, max, &number);
	*ret = (unsigned long)number;

	return result;
}

int string_to_number(const char *s, unsigned int min, unsigned int max, unsigned int *ret) {
	int result;
	unsigned long number;

	result = string_to_number_l(s, min, max, &number);
	*ret = (unsigned int)number;

	return result;
}

/*
 * $Log: parse_port.c,v $
 * Revision 1.1  2006/04/17 13:27:35  brugge
 * Version estable.
 *
 * Revision 1.4  2006/04/16 14:48:53  brugge
 * Se agregó un parámetro a la función parse_ports().
 *
 * Revision 1.3  2006/04/10 23:41:47  brugge
 * Se agregaron las funciones string_to_number() (del archivo iptables.h).
 * Se modificó el prototipo de la función parse_ports() y se modificó el
 * for de la implementación.
 *
 * Revision 1.2  2006/04/10 21:52:12  brugge
 * Se modificó la implementación de la función parse_ports().
 * Se agregó un límite de puertos a parsear.
 *
 * Revision 1.1  2006/04/10 20:47:55  brugge
 * Versión inicial.
 *
 */
