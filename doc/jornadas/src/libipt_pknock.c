#include <getopt.h>

#include <iptables.h>
#include "ipt_pknock.h"


static struct option opts[] = {
	{ .name = "option", 	.has_arg = 1,	.flag = 0,	.val = 'o' },
	{ .name = 0 }
};


/*
 * Imprime las parametros disponibles para el modulo.
 */
static void help(void) 
{

}


/*
 * Se llama al cargarse el módulo. Inicializa el match (se setean
 * valores por defecto.
 */
static void init(struct ipt_entry_match *m, unsigned int *nfcache) 
{

}


/*
 * Parsea la línea de comandos. Devuelve 1 si encuentra una opción.
 * Es llamada cada vez que se encuentra un argumento.
 */
static int parse(int c, char **argv, int invert, unsigned int *flags, 
		const struct ipt_entry *entry, 
		unsigned int *nfcache, 
		struct ipt_entry_match **match) 
{
	return 1;
}


/*
 * Esta función da una última oportunidad de verificar las reglas. Es llamada después
 * del parseo de los argumentos.
 */
static void final_check(unsigned int flags) 
{

}


/*
 * Imprime información sobre la regla. Es llamada por "iptables -L".
 */
static void print(const struct ipt_ip *ip, const struct ipt_entry_match *match, int numeric)
{

}


/*
 * Esta función muestra los argumentos cargados de una regla. Estos argumentos 
 * están almacenados en la estructura ipt_entry_match.
 *
 * Es llamada cuando se usa "iptables-save".
 */
static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match) 
{

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


void _init(void) 
{
	register_match(&pknock);
}
