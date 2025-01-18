/*
 * Copyright (c) 2004, Stefan Walter
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "usuals.h"

#include "compat.h"
#include "sock_any.h"
#include "stringx.h"
#include "smtppass.h"

/* -----------------------------------------------------------------------
 *  STRUCTURES
 */

typedef struct pxstate
{
    /* Settings ------------------------------- */
    int filter_type;                /* Type of filter: pipe, file, reject */
    const char* command;            /* The command to pipe email through */
    const char* reject;             /* SMTP code for FILTER_REJECT*/
    struct timeval timeout;         /* The command timeout */
    const char* directory;          /* The directory for temp files */
    const char* header;             /* Header to include in output */
}
pxstate_t;

/* -----------------------------------------------------------------------
 *  STRINGS
 */

enum {
	FILTER_PIPE = 1,
	FILTER_FILE = 2,
	FILTER_SMTP = 3,
	FILTER_REJECT = 4
};

#define REJECTED            "Content Rejected"

#define DEFAULT_REJECT      "530 Email Rejected"
#define DEFAULT_CONFIG      CONF_PREFIX "/proxsmtpd.conf"
#define DEFAULT_TIMEOUT     30

#define CFG_FILTERCMD       "FilterCommand"
#define CFG_FILTERREJECT    "FilterReject"
#define CFG_FILTERTYPE      "FilterType"
#define CFG_DIRECTORY       "TempDirectory"
#define CFG_DEBUGFILES      "DebugFiles"
#define CFG_CMDTIMEOUT      "FilterTimeout"
#define CFG_HEADER      	"Header"
#define CFG_REJECTPFX       "RejectMessagePrefix"

#define TYPE_PIPE           "pipe"
#define TYPE_FILE           "file"
#define TYPE_SMTP           "smtp"
#define TYPE_REJECT         "reject"

/* Poll time for waiting operations in milli seconds */
#define POLL_TIME           20

/* read & write ends of a pipe */
#define  READ_END   0
#define  WRITE_END  1

/* pre-set file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

/* -----------------------------------------------------------------------
 *  GLOBALS
 */

pxstate_t g_pxstate;

/* -----------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 */

static void usage();
static int process_file_command(spctx_t* sp);
static int process_pipe_command(spctx_t* sp);
static int process_smtp_command(spctx_t* sp);
static void final_reject_message(char* buf, int buflen);
static void buffer_reject_message(char* data, char* buf, int buflen);
static int kill_process(spctx_t* sp, pid_t pid);
static int wait_process(spctx_t* sp, pid_t pid, int* status);

/* ----------------------------------------------------------------------------------
 *  STARTUP ETC...
 */

#ifndef HAVE___ARGV
char** __argv;
#endif

int main(int argc, char* argv[])
{
    const char* configfile = DEFAULT_CONFIG;
    const char* pidfile = NULL;
    int dbg_level = -1;
    int ch = 0;
    int r;
    char* t;

#ifndef HAVE___ARGV
    __argv = argv;
#endif

    /* Setup some defaults */
    memset(&g_pxstate, 0, sizeof(g_pxstate));
    g_pxstate.directory = _PATH_TMP;
    g_pxstate.filter_type = FILTER_PIPE;
    g_pxstate.timeout.tv_sec = DEFAULT_TIMEOUT;
    g_pxstate.reject = DEFAULT_REJECT;
    g_pxstate.rejectPrefix = REJECTED;

    sp_init("proxsmtpd");

    /*
     * We still accept our old arguments for compatibility reasons.
     * We fill them into the spstate structure directly
     */

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "d:f:p:v")) != -1)
    {
        switch(ch)
        {
		/*  Don't daemonize  */
        case 'd':
            dbg_level = strtol(optarg, &t, 10);
            if(*t) /* parse error */
                errx(1, "invalid debug log level");
            dbg_level += LOG_ERR;
            break;

        /* The configuration file */
        case 'f':
            configfile = optarg;
            break;

        /* Write out a pid file */
        case 'p':
            pidfile = optarg;
            break;

        /* Print version number */
        case 'v':
            printf("proxsmtpd (version %s)\n", VERSION);
            printf("          (config: %s)\n", DEFAULT_CONFIG);
            exit(0);
            break;

        /* Usage information */
        case '?':
        default:
            usage();
            break;
		}
    }

	argc -= optind;
	argv += optind;

    if(argc > 0)
        usage();

    r = sp_run(configfile, pidfile, dbg_level);

    sp_done();

    return r;
}

static void usage()
{
    fprintf(stderr, "usage: proxsmtpd [-d debuglevel] [-f configfile] [-p pidfile]\n");
    fprintf(stderr, "       proxsmtpd -v\n");
    exit(2);
}

/* ----------------------------------------------------------------------------------
 *  SP CALLBACKS
 */

int cb_check_pre(spctx_t* ctx)
{
	if(g_pxstate.filter_type == FILTER_REJECT)
	{
		sp_add_log(ctx, "status=", "REJECTED");
		if(sp_fail_msg(ctx, g_pxstate.reject) < 0)
			return -1; /* Message already printed */
		return 0;
	}

	return 1;
}

int cb_check_data(spctx_t* ctx)
{
    int r = 0;

    if(g_pxstate.filter_type == FILTER_REJECT)
    {
        sp_add_log(ctx, "status=", "REJECTED");
        if(sp_fail_data(ctx, g_pxstate.reject) < 0)
            return -1; /* Message already printed */
        return 0;
    }

    /* Tell client to start sending data */
    if(sp_start_data (ctx) < 0)
        return -1; /* Message already printed */

    if(!g_pxstate.command)
    {
        sp_messagex(ctx, LOG_WARNING, "no filter command specified. passing message through");

        if(sp_cache_data(ctx) == -1 ||
           sp_done_data(ctx, g_pxstate.header) == -1)
            return -1;  /* Message already printed */
        return 0;
    }

    /* Cleanup any old filters hanging around */
    while(waitpid(-1, &r, WNOHANG) > 0)
        ;

    if(g_pxstate.filter_type == FILTER_PIPE)
        r = process_pipe_command(ctx);
    else if(g_pxstate.filter_type == FILTER_SMTP)
        r = process_smtp_command(ctx);
    else
        r = process_file_command(ctx);

    if(r == -1)
    {
        if(sp_fail_data(ctx, NULL) == -1)
            return -1;
    }

    return 0;
}

int cb_parse_option(const char* name, const char* value)
{
    char* t;

    if(strcasecmp(CFG_FILTERCMD, name) == 0)
    {
        g_pxstate.command = value;
        return 1;
    }

    else if(strcasecmp(CFG_DIRECTORY, name) == 0)
    {
        g_pxstate.directory = value;
        return 1;
    }

    else if(strcasecmp(CFG_CMDTIMEOUT, name) == 0)
    {
        g_pxstate.timeout.tv_sec = strtol(value, &t, 10);
        if(*t || g_pxstate.timeout.tv_sec <= 0)
            errx(2, "invalid setting: " CFG_CMDTIMEOUT);
        return 1;
    }

    else if(strcasecmp(CFG_FILTERTYPE, name) == 0)
    {
        if(strcasecmp(value, TYPE_PIPE) == 0)
            g_pxstate.filter_type = FILTER_PIPE;
        else if(strcasecmp(value, TYPE_FILE) == 0)
            g_pxstate.filter_type = FILTER_FILE;
        else if(strcasecmp(value, TYPE_SMTP) == 0)
            g_pxstate.filter_type = FILTER_SMTP;
        else if(strcasecmp(value, TYPE_REJECT) == 0)
            g_pxstate.filter_type = FILTER_REJECT;
        else
            errx(2, "invalid value for " CFG_FILTERTYPE
                 " (must specify '" TYPE_PIPE "' or '" TYPE_FILE "' or '" TYPE_REJECT "')");
        return 1;
    }

    else if(strcasecmp(CFG_FILTERREJECT, name) == 0)
    {
        g_pxstate.reject = value;
        return 1;
    }

    else if(strcasecmp(CFG_REJECTPFX, name) == 0)
    {
        g_pxstate.rejectPrefix = value;
        return 1;
    }

    else if(strcasecmp(CFG_HEADER, name) == 0)
    {
        g_pxstate.header = trim_start(value);
        if(strlen(g_pxstate.header) == 0)
            g_pxstate.header = NULL;
        return 1;
    }

    return 0;
}

spctx_t* cb_new_context()
{
    spctx_t* ctx = (spctx_t*)calloc(1, sizeof(spctx_t));
    if(!ctx)
        sp_messagex(NULL, LOG_CRIT, "out of memory");
    return ctx;
}

void cb_del_context(spctx_t* ctx)
{
    free(ctx);
}

/* -----------------------------------------------------------------------------
 * IMPLEMENTATION
 */

static void kill_myself()
{
    while (1) {
        kill(getpid(), SIGKILL);
        sleep(1);
    }
}

static pid_t fork_filter(spctx_t* sp, int* infd, int* outfd, int* errfd)
{
    pid_t pid;
    int ret = 0;
    int r = 0, open_max;

    /* Pipes for input, output, err */
    int pipe_i[2];
    int pipe_o[2];
    int pipe_e[2];

    memset(pipe_i, ~0, sizeof(pipe_i));
    memset(pipe_o, ~0, sizeof(pipe_o));
    memset(pipe_e, ~0, sizeof(pipe_e));

    ASSERT(g_pxstate.command);

    /* Create the pipes we need */
    if((infd && pipe(pipe_i) == -1) ||
       (outfd && pipe(pipe_o) == -1) ||
       (errfd && pipe(pipe_e) == -1))
    {
        sp_message(sp, LOG_ERR, "couldn't create pipe for filter command");
        RETURN(-1);
    }

    /* Now fork the pipes across processes */
    switch(pid = fork())
    {
    case -1:
        sp_message(sp, LOG_ERR, "couldn't fork for filter command");
        RETURN(-1);

    /* The child process */
    case 0:

        if(r >= 0 && infd)
        {
            close(pipe_i[WRITE_END]);
            r = dup2(pipe_i[READ_END], STDIN);
			close(pipe_i[READ_END]);
        }

        if(r >= 0 && outfd)
        {
            close(pipe_o[READ_END]);
            r = dup2(pipe_o[WRITE_END], STDOUT);
			close(pipe_o[WRITE_END]);
        }

        if(r >= 0 && errfd)
        {
            close(pipe_e[READ_END]);
            r = dup2(pipe_e[WRITE_END], STDERR);
			close(pipe_e[WRITE_END]);
        }

        if(r < 0)
        {
            sp_message(sp, LOG_ERR, "couldn't dup descriptors for filter command");
            kill_myself();
        }

        open_max = sysconf(_SC_OPEN_MAX);
        for (r = 3; r < open_max; ++r)
            close(r);

        /* All the necessary environment vars */
        sp_setup_forked(sp, 1);

        /* Now run the filter command */
        execl("/bin/sh", "sh", "-c", g_pxstate.command, NULL);

        /* If that returned then there was an error */
        sp_message(sp, LOG_ERR, "error executing the shell for filter command");
        kill_myself();
        break;
    };

    /* The parent process */
    sp_messagex(sp, LOG_DEBUG, "executed filter command: %s (pid: %d)", g_pxstate.command, (int)pid);

    /* Setup all our return values */
    if(infd)
    {
        *infd = pipe_i[WRITE_END];
        pipe_i[WRITE_END] = -1;
        fcntl(*infd, F_SETFL, fcntl(*infd, F_GETFL, 0) | O_NONBLOCK);
    }

    if(outfd)
    {
        *outfd = pipe_o[READ_END];
        pipe_o[READ_END] = -1;
        fcntl(*outfd, F_SETFL, fcntl(*outfd, F_GETFL, 0) | O_NONBLOCK);
    }

    if(errfd)
    {
        *errfd = pipe_e[READ_END];
        pipe_e[READ_END] = -1;
        fcntl(*errfd, F_SETFL, fcntl(*errfd, F_GETFL, 0) | O_NONBLOCK);
    }

cleanup:
    if(pipe_i[READ_END] != -1)
        close(pipe_i[READ_END]);
    if(pipe_i[WRITE_END] != -1)
        close(pipe_i[WRITE_END]);
    if(pipe_o[READ_END] != -1)
        close(pipe_o[READ_END]);
    if(pipe_o[WRITE_END] != -1)
        close(pipe_o[WRITE_END]);
    if(pipe_e[READ_END] != -1)
        close(pipe_e[READ_END]);
    if(pipe_e[WRITE_END] != -1)
        close(pipe_e[WRITE_END]);

    return ret >= 0 ? pid : (pid_t)-1;
}

static int process_file_command(spctx_t* sp)
{
    pid_t pid = 0;
    int ret = 0, status, r;
    struct timeval timeout;

    /* For reading data from the process */
    int errfd;
    fd_set rmask;
    char obuf[1024];
    char ebuf[256];

    memset(ebuf, 0, sizeof(ebuf));

    if(sp_cache_data(sp) == -1)
        RETURN(-1); /* message already printed */

    pid = fork_filter(sp, NULL, NULL, &errfd);
    if(pid == (pid_t)-1)
        RETURN(-1);

    /* Main read write loop */
    while(errfd != -1)
    {
        FD_ZERO(&rmask);
        FD_SET(errfd, &rmask);

        /* Select can modify the timeout argument so we copy */
        memcpy(&timeout, &(g_pxstate.timeout), sizeof(timeout));

        r = select(errfd + 1, &rmask, NULL, NULL, &timeout);

        switch(r)
        {
        case -1:
            sp_message(sp, LOG_ERR, "couldn't select while listening to filter command");
            RETURN(-1);
        case 0:
            sp_messagex(sp, LOG_ERR, "timeout while listening to filter command");
            RETURN(-1);
        };

        ASSERT(FD_ISSET(errfd, &rmask));

        /* Note because we handle as string we save one byte for null-termination */
        r = read(errfd, obuf, sizeof(obuf) - 1);
        if(r < 0)
        {
            if(errno != EINTR && errno != EAGAIN)
            {
                sp_message(sp, LOG_ERR, "couldn't read data from filter command");
                RETURN(-1);
            }

            continue;
        }

        if(r == 0)
        {
            close(errfd);
            errfd = -1;
            break;
        }

        /* Null terminate */
        obuf[r] = 0;

        /* And process */
        buffer_reject_message(obuf, ebuf, sizeof(ebuf));

        if(sp_is_quit())
            RETURN(-1);
    }

    /* exit the process if not completed */
    if(wait_process(sp, pid, &status) == -1)
    {
        sp_messagex(sp, LOG_ERR, "timeout waiting for filter command to exit");
        RETURN(-1);
    }

    pid = 0;

    /* We only trust well behaved programs */
    if(!WIFEXITED(status))
    {
        sp_messagex(sp, LOG_ERR, "filter command terminated abnormally");
        RETURN(-1);
    }

    sp_messagex(sp, LOG_DEBUG, "filter exit code: %d", (int)WEXITSTATUS(status));

    /* A successful response */
    if(WEXITSTATUS(status) == 0)
    {
        if(sp_done_data(sp, g_pxstate.header) == -1)
            RETURN(-1); /* message already printed */

        sp_add_log(sp, "status=", "FILTERED");
    }

    /* Check code and use stderr if bad code */
    else
    {
        final_reject_message(ebuf, sizeof(ebuf));

        if(sp_fail_data(sp, ebuf) == -1)
            RETURN(-1); /* message already printed */

        sp_add_log(sp, "status=", ebuf);
    }

    ret = 0;

cleanup:

    if(pid != 0)
    {
        sp_messagex(sp, LOG_WARNING, "killing filter process (pid %d)", (int)pid);
        kill_process(sp, pid);
    }

    if(errfd != -1)
        close(errfd);

    if(ret < 0)
        sp_add_log(sp, "status=", "FILTER-ERROR");

    return ret;
}

static int smtp_command(int s, char* data, char* resp, char** resp_data)
{
	char buf[4096];
	int t;
	if (data && send(s, data, strlen(data), 0) != strlen(data))
		return -1;
	if ((t=recv(s, buf, sizeof buf, 0)) > 0) {
		buf[t] = '\0';
		if (resp_data)
			*resp_data = strdup(buf);
		if (!resp || strncmp(buf, resp, strlen(resp)) == 0)
			return 0;
	}
	return -1;
}

static int process_smtp_command(spctx_t* sp)
{
	int ret = 0;
	int s = -1;
	int fd = -1, t;
	struct sockaddr_in remote;
	char *last_line = NULL, *recipients = NULL;
	char str[4096];

	if(sp_cache_data(sp) == -1)
		RETURN(-1); /* message already printed */

	if (!sp->sender || !sp->recipients) {
		syslog(LOG_WARNING, "missing sender or recipient");
		RETURN(-1);
	}

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_WARNING, "socket: %m");
		RETURN(-1);
	}

	memset(&remote, 0, sizeof(struct sockaddr_in));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(25);
	remote.sin_addr.s_addr = inet_addr(g_pxstate.command);

	if (connect(s, (struct sockaddr *)&remote, sizeof(struct sockaddr_in)) == -1) {
		syslog(LOG_WARNING, "connect: %m");
		RETURN(-1);
	}

	if (smtp_command(s, NULL, "220", NULL) == -1) {
		syslog(LOG_WARNING, "smtp_command(%s): %m", str);
		RETURN(-1);
	}

	snprintf(str, sizeof str, "EHLO proxsmtp\r\n");
	if (smtp_command(s, str, "250", NULL) == -1) {
		syslog(LOG_WARNING, "smtp_command(%s): %m", str);
		RETURN(-1);
	}

	if (sp->helo)
		snprintf(str, sizeof str, "XCLIENT ADDR=%s%s HELO=%s\r\n", strchr(sp->client.peername, ':') ? "IPv6:" : "", sp->client.peername, sp->helo);
	else
		snprintf(str, sizeof str, "XCLIENT ADDR=%s%s\r\n", strchr(sp->client.peername, ':') ? "IPv6:" : "", sp->client.peername);
	if (smtp_command(s, str, "220", NULL) == -1) {
		syslog(LOG_WARNING, "smtp_command(%s): %m", str);
		RETURN(-1);
	}

	snprintf(str, sizeof str, "MAIL FROM: %s\r\n", sp->sender);
	if (smtp_command(s, str, "250", NULL) == -1) {
		syslog(LOG_WARNING, "smtp_command(%s): %m", str);
		RETURN(-1);
	}

	char *r = recipients = strdup(sp->recipients);
	char *token;
	while ((token = strsep(&r, "\n")) != NULL) {
		snprintf(str, sizeof str, "RCPT TO: %s\r\n", token);
		if (smtp_command(s, str, "250", &last_line) == -1) {
			if (!last_line) {
				syslog(LOG_WARNING, "smtp_command(%s): %m", str);
				RETURN(-1);
			}
			trim_end(last_line);
			if (sp_fail_data(sp, last_line) == -1)
				RETURN(-1); /* message already printed */
			sp_add_log(sp, "status=", last_line);
			RETURN(0);
		}
		free(last_line);
		last_line = NULL;
	}

	snprintf(str, sizeof str, "DATA\r\n");
	if (smtp_command(s, str, "354", NULL) == -1) {
		syslog(LOG_WARNING, "smtp_command(%s): %m", str);
		RETURN(-1);
	}

	if ((fd = open(sp->cachename, O_RDONLY)) == -1) {
		syslog(LOG_WARNING, "open(%s): %m", sp->cachename);
		RETURN(-1);
	}

	char buf[4096];
	while ((t=read(fd, buf, sizeof buf)) > 0)
		if (send(s, buf, t, 0) != t)
			RETURN(-1);

	snprintf(str, sizeof str, ".\r\n");
	if (smtp_command(s, str, NULL, &last_line) == -1) {
		syslog(LOG_WARNING, "smtp_command(%s): %m", str);
		RETURN(-1);
	}

	trim_end(last_line);
	snprintf(str, sizeof str, "QUIT\r\n");
	smtp_command(s, str, NULL, NULL);

	const char* accept = "250 2.0.0 OK:";
	if (strncmp(last_line, accept, strlen(accept)) == 0) {
		if (sp_done_data(sp, g_pxstate.header) == -1)
			RETURN(-1); /* message already printed */
		sp_add_log(sp, "status=", "FILTERED");
	} else {
		if (sp_fail_data(sp, last_line) == -1)
			RETURN(-1); /* message already printed */
		sp_add_log(sp, "status=", last_line);
	}
	ret = 0;

cleanup:
	if (ret < 0)
		sp_add_log(sp, "status=", "FILTER-ERROR");
	if (s != -1)
		close(s);
	if (fd != -1)
		close(fd);
	free(last_line);
	free(recipients);
	return ret;
}

static int process_pipe_command(spctx_t* sp)
{
    pid_t pid;
    int ret = 0, status, r;
    struct timeval timeout;

    /* For sending data to the process */
    const char* ibuf = NULL;
    int ilen = 0;
    int infd;
    int icount = 0;
    fd_set wmask;

    /* For reading data from the process */
    int nfds = -1;
    int outfd;
    int errfd;
    fd_set rmask;
    char obuf[1024];
    char ebuf[256];
    int ocount = 0;

    ASSERT(g_pxstate.command);

    memset(ebuf, 0, sizeof(ebuf));

    pid = fork_filter(sp, &infd, &outfd, &errfd);
    if(pid == (pid_t)-1)
        RETURN(-1);

    /* Opens cache file */
    if(sp_write_data(sp, obuf, 0) == -1)
        RETURN(-1); /* message already printed */

    /* Main read write loop */
    while(infd != -1 || outfd != -1 || errfd != -1)
    {
        FD_ZERO(&rmask);
        FD_ZERO(&wmask);

        /* We only select on those that are still open */
        if(infd != -1)
            FD_SET(infd, &wmask);
        nfds = infd > nfds ? infd : nfds;

        if(outfd != -1)
            FD_SET(outfd, &rmask);
        nfds = outfd > nfds ? outfd : nfds;

        if(errfd != -1)
            FD_SET(errfd, &rmask);
        nfds = errfd > nfds ? errfd : nfds;

        /* Select can modify the timeout argument so we copy */
        memcpy(&timeout, &(g_pxstate.timeout), sizeof(timeout));

        r = select(nfds + 1, &rmask, &wmask, NULL, &timeout);
        switch(r)
        {
        case -1:
            sp_message(sp, LOG_ERR, "couldn't select while listening to filter command");
            RETURN(-1);
        case 0:
            sp_messagex(sp, LOG_WARNING, "timeout while listening to filter command");
            RETURN(-1);
        };

        /* Handling of process's stdin */
        if(infd != -1 && FD_ISSET(infd, &wmask))
        {
            if(ilen <= 0)
            {
                /* Read some more data into buffer */
                switch(r = sp_read_data(sp, &ibuf))
                {
                case -1:
                    RETURN(-1);  /* Message already printed */
                case 0:
                    close(infd); /* Done with the input */
                    infd = -1;
                    break;
                default:
                    ASSERT(r > 0);
                    ilen = r;
                    break;
                };
            }

            if(ilen > 0)
            {
                /* Write data from buffer */
                r = write(infd, ibuf, ilen);
                if(r == -1)
                {
                    if(errno == EPIPE)
                    {
                        sp_messagex(sp, LOG_INFO, "filter command closed input early");

                        /* Eat up the rest of the data */
                        while(sp_read_data(sp, &ibuf) > 0)
                            ;

                        close(infd);
                        infd = -1;
                    }
                    else if(errno != EAGAIN && errno != EINTR)
                    {
                        /* Otherwise it's a normal error */
                        sp_message(sp, LOG_ERR, "couldn't write to filter command");
                        RETURN(-1);
                    }
                }

                /* A good normal write */
                else
                {
                    icount += r;
                    ilen -= r;
                    ibuf += r;
                }
            }
        }

        /* Handling of stdout, which should be email data */
        if(outfd != -1 && FD_ISSET(outfd, &rmask))
        {
            r = read(outfd, obuf, sizeof(obuf));
            if(r > 0)
            {
                if(sp_write_data(sp, obuf, r) == -1)
                    RETURN(-1); /* message already printed */

                ocount += r;
            }

            else if(r == 0)
            {
                close(outfd);
                outfd = -1;
            }

            else if(r < 0)
            {
                if(errno != EINTR && errno != EAGAIN)
                {
                    sp_message(sp, LOG_ERR, "couldn't read data from filter command");
                    RETURN(-1);
                }
            }
        }

        /* Handling of stderr, the last line of which we use as an err message*/
        if(errfd != -1 && FD_ISSET(errfd, &rmask))
        {
            /* Note because we handle as string we save one byte for null-termination */
            r = read(errfd, obuf, sizeof(obuf) - 1);
            if(r < 0)
            {
                if(errno != EINTR && errno != EAGAIN)
                {
                    sp_message(sp, LOG_ERR, "couldn't read data from filter command");
                    RETURN(-1);
                }
            }

            else if(r == 0)
            {
                close(errfd);
                errfd = -1;
            }

            else if(r > 0)
            {
                /* Null terminate */
                obuf[r] = 0;

                /* And process */
                buffer_reject_message(obuf, ebuf, sizeof(ebuf));
            }
        }

        if(sp_is_quit())
            RETURN(-1);
    }

    sp_messagex(sp, LOG_DEBUG, "wrote %d bytes to filter, read %d bytes", icount, ocount);

    /* Close the cache file */
    if(sp_write_data(sp, NULL, 0) == -1)
        RETURN(-1); /* message already printed */

    if(wait_process(sp, pid, &status) == -1)
    {
        sp_messagex(sp, LOG_ERR, "timeout waiting for filter command to exit");
        RETURN(-1);
    }

    pid = 0;

    /* We only trust well behaved programs */
    if(!WIFEXITED(status))
    {
        sp_messagex(sp, LOG_ERR, "filter command terminated abnormally");
        RETURN(-1);
    }

    sp_messagex(sp, LOG_DEBUG, "filter exit code: %d", (int)WEXITSTATUS(status));

    /* A successful response */
    if(WEXITSTATUS(status) == 0)
    {
        if(sp_done_data(sp, g_pxstate.header) == -1)
            RETURN(-1); /* message already printed */

        sp_add_log(sp, "status=", "FILTERED");
    }

    /* Check code and use stderr if bad code */
    else
    {
        final_reject_message(ebuf, sizeof(ebuf));

        if(sp_fail_data(sp, ebuf) == -1)
            RETURN(-1); /* message already printed */

        sp_add_log(sp, "status=", ebuf);
    }

    ret = 0;

cleanup:

    if(infd != -1)
        close(infd);
    if(outfd != -1)
        close(outfd);
    if(errfd != -1)
        close(errfd);

    if(pid != 0)
    {
        sp_messagex(sp, LOG_WARNING, "killing filter process (pid %d)", (int)pid);
        kill_process(sp, pid);
    }

    if(ret < 0)
        sp_add_log(sp, "status=", "FILTER-ERROR");

    return ret;
}

static void final_reject_message(char* buf, int buflen)
{
    if(buf[0] == 0)
        strlcpy(buf, g_pxstate.rejectPrefix, buflen);
    else
        trim_end(buf);
}

static void buffer_reject_message(char* data, char* buf, int buflen)
{
    int len = strlen(data);
    char* t = data + len;
    int newline = 0;

    while(t > data && isspace(*(t - 1)))
    {
        t--;

        if(*t == '\n')
            newline = 1;
    }

    /* No valid line */
    if(t > data)
    {
        if(newline)
            *t = 0;

        t = strrchr(data, '\n');
        if(t == NULL)
        {
            t = trim_start(data);

            /*
             * Basically if we already have a newline at the end
             * then we need to start a new line
             */
			if(buf[strlen(buf) - 1] == '\n')
                buf[0] = 0;
        }
        else
        {
            t = trim_start(t);

            /* Start a new line */
            buf[0] = 0;
        }

        /* t points to a valid line */
        strlcat(buf, t, buflen);
    }

    /* Always append if we found a newline */
    if(newline)
        strlcat(buf, "\n", buflen);
}

static int wait_process(spctx_t* sp, pid_t pid, int* status)
{
    /* We poll x times a second */
    int waits = g_pxstate.timeout.tv_sec * (1000 / POLL_TIME);
    *status = 0;

    while(waits > 0)
    {
        switch(waitpid(pid, status, WNOHANG))
        {
        case 0:
	    /* Linux may return 0 if the task has already terminated and was
	     * caught by waitpid(-1) above, double check it still exists.
	     */
            if (kill(pid, 0) < 0 && errno == ESRCH)
                return 0;
            break;
        case -1:
            if(errno != ECHILD && errno != ESRCH)
            {
                sp_message(sp, LOG_CRIT, "error waiting on process");
                return -1;
            }
            /* fall through */
        default:
            return 0;
        }

        usleep(POLL_TIME * 1000);
        waits--;
    }

    return -1;
}

static int kill_process(spctx_t* sp, pid_t pid)
{
    int status;

    if(kill(pid, SIGTERM) == -1)
    {
        if(errno == ESRCH)
            return 0;

        sp_message(sp, LOG_ERR, "couldn't send signal to process");
        return -1;
    }

    if(wait_process(sp, pid, &status) == -1)
    {
        if(kill(pid, SIGKILL) == -1)
        {
            if(errno == ESRCH)
                return 0;

            sp_message(sp, LOG_ERR, "couldn't send signal to process");
            return -1;
        }

        sp_messagex(sp, LOG_ERR, "process wouldn't quit. forced termination");
    }

   return 0;
}
