#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <libnetpkt.h>

static int
not_here(char *s)
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(char *name, int len, int arg)
{
    errno = EINVAL;
    return 0;
}

MODULE = Net::Pkt		PACKAGE = Net::Pkt		


double
constant(sv,arg)
    PREINIT:
	STRLEN		len;
    INPUT:
	SV *		sv
	char *		s = SvPV(sv, len);
	int		arg
    CODE:
	RETVAL = constant(s,len,arg);
    OUTPUT:
	RETVAL


int
netpkt_open_l2(arg0)
	char *	arg0
