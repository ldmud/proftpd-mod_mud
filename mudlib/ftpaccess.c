// The function 'FtpAccess()' is located within our master-object and is
// called by receive_imp(). It is responsible for the communication with
// ProFtpd and controls the access rights.

static void FtpAccess( string host, string message, int port )
{
    string *comp, reply, head;

#if __EFUN_DEFINED__(send_imp)
    comp = efun::explode( message, "\t" );
#define FTP_ID   0
#define FTP_SEQ  1
#define FTP_TAG  2
#define FTP_CMD  3
#define FTP_ARG1 4
#define FTP_ARG2 5
#define FTP_ARG3 6

    // unknown requests are logged
    if ( sizeof(comp) <= FTP_CMD || lower_case(comp[FTP_TAG]) != "req" ){
        log_file( "IMP_MSGS", "Host: " + host + ":" + port + " - '" +
                  message + "'\n" );
        return;
    }

    // prepare the answer; default is 'not allowed'
    reply = "INVALID";
    head = sprintf( "%s\t%s\tRPLY\t%s\t",
                    comp[FTP_ID], comp[FTP_SEQ], comp[FTP_CMD] );


    // now let's see what is requested:
    switch ( lower_case(comp[FTP_CMD]) ){
    // a user wants to log in; test if it is a valid account
    case "user":
        if ( sizeof(comp) <= FTP_ARG1 )
            break;
        
        // only wizards have ftp-accounts
        // anonymous accounts are handled by ProFtpd
        if ( IS_LEARNER(lower_case(comp[FTP_ARG1])) )
            reply = "/players/" + lower_case(comp[FTP_ARG1]);
        else
            reply = "NONE";
        break;

    // authenticate user; does password match username?
    case "pass":
        if ( sizeof(comp) <= FTP_ARG2 )
            break;
        
        comp[FTP_ARG1] = lower_case(comp[FTP_ARG1]);
        
        // only wizards have ftp-accounts
        // anonymous accounts are handled by ProFtpd
        if ( IS_LEARNER(comp[FTP_ARG1]) ){ 
            if ( CheckPasswd( comp[FTP_ARG1], comp[FTP_ARG2] ) )
                reply = "OK";
            else 
                // failed logins are logged
                log_file( "LOGINFAIL",
                          sprintf( "BAD PASSWORD:      (FTP)     %s %s\n",
                                   comp[FTP_ARG1],
                                   ctime(time()) ) );
        }
        else 
            reply = "FAIL";
        break;

    // user wants to read files; is he allowed to?
    case "read":
        if ( sizeof(comp) <= FTP_ARG2 )
            break;
        
        if ( comp[FTP_ARG2][0] == '/' &&
             // check if read-access is valid
             // access-rights for anonymous accounts are handled by ProtFpd
             valid_read( comp[FTP_ARG2], lower_case(comp[FTP_ARG1]),
                         "read_file", 0 ) )
            reply = "OK";
        else
            reply = "FAIL";
        break;

    // is user allowed to write the given file?
    case "writ":
        if ( sizeof(comp) <= FTP_ARG2 )
            break;
        
        if ( comp[FTP_ARG2][0] == '/' &&
             // the same as above
             valid_write( comp[FTP_ARG2], lower_case(comp[FTP_ARG1]),
                          "write_file", 0 ) )
            reply = "OK";
        else
            reply = "FAIL";
        break;

    // is user allowed to list contents of directory?
    // NOTE: you need permissions to list the contents of a directory
    // to 'cd' into it with ProFtpd
    case "list":
        if ( sizeof(comp) <= FTP_ARG2 )
            break;
        
        if ( comp[FTP_ARG2][0] == '/' &&
             // In contrast to NaseFtp, the mud-module for ProFtpd
             // only expects "OK" or "FAIL" as an answer to the list-command.
             // The directory listing is built by ProFtpd itself.
             // Thus it is possible that a user can see a file but isn't
             // allowed to read it`s contents.
             // This solution isn't as flexible as the way NaseFtp handles
             // directory listings, but it is _way_ faster.
             valid_read( comp[FTP_ARG2], lower_case(comp[FTP_ARG1]),
                         "read_file", 0 ) )
            reply = "OK";
        else
            reply = "FAIL";
        break;
        
    default:
        // unknown requests are logged
        log_file( "IMP_MSGS", "Host: " + host + ":" + port + " - '" +
                  message + "'\n" );
        break;
    }

    // send the answer
    send_imp( host, port, head+reply );
#endif
}
