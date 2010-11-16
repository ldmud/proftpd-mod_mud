#ifndef _MUD_H_
#define _MUD_H_ 1

/*
 * mod_mud.c: mud-user login&file access handling
 * Bas
 * @author Wolfgang Hamann, wolfgang@blitzstrahl
 *
 * @author Tiamak@MorgenGrauen
 * @author Matthias L. Jugel, MorgenGrauen
 * @author Peng@FinalFrontier (original)
 *
 * $Id: mod_mud.c,v 1.4 Son Jun 22 00:50:14 CEST 2003 mud Exp $
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
