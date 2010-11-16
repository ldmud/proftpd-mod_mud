#ifndef _MUD_H_
#define _MUD_H_ 1

/*
 * Configuration for mud module for proftpd.
 *
 * @author Tiamak@MorgenGrauen
 * @author Matthias L. Jugel, MorgenGrauen
 * @author Peng@FinalFrontier (original)
 *
 * $Id: mud.h,v 1.1.1.1 1999/08/27 17:54:59 mud Exp $
 */

#include <pwd.h>
#include <netinet/in.h>

/* How many retries before aborting an UDP comm attempt?  */
#ifndef UDP_RETRIES
#define UDP_RETRIES 2
#endif

/* Time to wait between two UDP retries, in seconds?  */
#ifndef UDP_DELAY
#define UDP_DELAY 2
#endif

struct mudpw {
  struct passwd pw; /* Standard pwd information */
  char pw_position[20];
  int pw_level;
  char pw_rdir[256]; /* relative to PATH_MUDLIB */
  char pw_domains[256];
};
 
#endif
