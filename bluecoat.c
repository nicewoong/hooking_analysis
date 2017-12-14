#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <resolv.h>
#include <errno.h>
#include <sys/un.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <execinfo.h>
#include <net/if.h>
#include <time.h>
#include <sys/epoll.h>
#include <poll.h>


#define SYSLOG 10
#define VLOG 11
int TRACE_LOG_MEDIA = VLOG;

#define UNUSED(x) (void)(x)
#define isManagedSockDomain(x) ((x)== AF_INET || (x)== AF_INET6 || (x)== AF_FILE)
#define PRINT_BUF_SIZE 2048
#define PRINT_LIMIT (p >= (((char*)printBuf)+PRINT_BUF_SIZE-1) ? 0 : (((char*)printBuf)+PRINT_BUF_SIZE-1-p))
#define isPrintableChar(x) (31<=(x) && (x) <127)
#define ERR_STRING (ret < 0 ? errString (save_errno) : "")
#define DEBUG_LOG_FD        524

char *__progname; // Program name, from crt0.
#define PROGNAME_LEN 16
#define HOSTNAME_LEN 64
static char progName[PROGNAME_LEN] = {"-"};
static char hname[HOSTNAME_LEN] = {"-"}; // bctak: 64 bytes should be sufficient to hold hostname
static struct timespec debug_ts1;
static struct timespec debug_ts2;
# define SET_START_TIME() { clock_gettime(CLOCK_REALTIME, &debug_ts1); }
# define SET_END_TIME() { clock_gettime(CLOCK_REALTIME, &debug_ts2); }
#define logerr(format,...) \
    ( \
    { \
        char ____buf[PRINT_BUF_SIZE]; \
        snprintf (____buf, PRINT_BUF_SIZE-1, __FILE__ ":%d " format, __LINE__, ##__VA_ARGS__); \
        ____buf[PRINT_BUF_SIZE-1] = 0; \
        syslog (LOG_INFO, "%s", ____buf); \
        libc_write (2, ____buf, strlen(____buf)); \
    })
#define debug_print(format,...) \
    ( \
    { \
        char ____buf[PRINT_BUF_SIZE]; \
        snprintf (____buf, PRINT_BUF_SIZE-1, format, ##__VA_ARGS__); \
        ____buf[PRINT_BUF_SIZE-1] = 0; \
        __debug_print (____buf); \
    })
# define dbg(format,...) ({ \
	long diffsec = debug_ts2.tv_sec - debug_ts1.tv_sec; \
	long diffns = debug_ts2.tv_nsec - debug_ts1.tv_nsec; \
	if (diffns<0) { \
		diffsec--; \
		diffns = 1000000000 - diffns; \
	} \
	if (TRACE_LOG_MEDIA == SYSLOG) { \
		syslog(LOG_INFO,"%ld.%09ld %ld.%09ld %s %s %05d %lx " format, debug_ts1.tv_sec, debug_ts1.tv_nsec, diffsec, diffns, \
			 progName, hname, getpid(), (unsigned long)pthread_self(), ##__VA_ARGS__); }\
	else { \
            debug_print ("%ld.%09ld %ld.%09ld %s %s %05d %lx " format, debug_ts1.tv_sec, debug_ts1.tv_nsec, \
                  diffsec, diffns, \
                  progName, hname, getpid(), (unsigned long)pthread_self(), ##__VA_ARGS__); }\
    })

ssize_t (*libc_write)(int fd, const void *buf, size_t nbyte);
ssize_t (*libc_writev) (int fd, const struct iovec * iov, int iovcnt);
ssize_t (*libc_send) (int fd, const void *buf, size_t len, int flags);
ssize_t (*libc_sendto) (int fd, const void *buf, size_t len, int flags, const struct sockaddr * to, socklen_t tolen);
ssize_t (*libc_sendmsg) (int fd, const struct msghdr * msg, int flags);
ssize_t (*libc_sendfile) (int out_fd, int in_fd, off_t * offset, size_t count);
size_t (*libc_fwrite) (const void *ptr, size_t size, size_t nmemb, FILE *stream);
ssize_t (*libc_pwrite) (int fd, const void *buf, size_t count, off_t offset);
ssize_t (*libc_pwrite64) (int fd, const void *buf, size_t count, off64_t offset);
ssize_t (*libc_pwritev) (int fd, const struct iovec *iov, int iovcnt, off_t offset);

ssize_t (*libc_read)(int fd, const void *buf, size_t nbyte);
ssize_t (*libc_readv) (int fd, const struct iovec * iov, int iovcnt);
ssize_t (*libc_recv) (int s, void *buf, size_t len, int flags);
ssize_t (*libc_recvfrom) (int s, void *buf, size_t len, int flags, struct sockaddr * from, socklen_t * fromlen);
ssize_t (*libc_recvmsg) (int s, struct msghdr * msg, int flags);
size_t (*libc_fread) (void *ptr, size_t size, size_t nmemb, FILE *stream);
ssize_t (*libc_pread) (int fd, void *buf, size_t count, off_t offset);
ssize_t (*libc_pread64) (int fd, void *buf, size_t count, off64_t offset);
ssize_t (*libc_preadv) (int fd, const struct iovec *iov, int iovcnt, off_t offset);

pid_t (*libc_fork) (void);
int (*libc_socket) (int domain, int type, int protocol);
int (*libc_bind) (int sockfd, const struct sockaddr * my_addr, socklen_t addrlen);
int (*libc_accept) (int sockfd, struct sockaddr * remote, socklen_t * addrlen);
int (*libc_connect) (int sockfd, const struct sockaddr * serv_addr, socklen_t addrlen);
int (*libc_open) (const char *filename, int flags, ...);
int (*libc_open64) (const char *filename, int flags, ...);
int (*libc_close) (int fd);
int (*libc_dup) (int oldfd);
int (*libc_dup2) (int oldfd, int newfd);

int (*libc_execve) (const char *filename, char *const argv[], char *const envp[]);
int (*libc_execvp)(const char *file, char *const argv[]);
int (*libc_execv)(const char *path, char *const argv[]);
int (*libc_execl) (const char *path, const char *arg, ...);
int (*libc_execlp) (const char *file, const char *arg, ...);
int (*libc_execle) (const char *path, const char *arg, ...);

int (*libc_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
int (*libc_epoll_pwait)(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
int (*libc_epoll_create)(int size);
int (*libc_epoll_create1)(int flag);
int (*libc_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
int (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int (*libc_pselect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
int (*libc_ppoll) (struct pollfd * fds, nfds_t nfds, const struct timespec * timeout, const sigset_t * sigmask);
int (*libc_poll) (struct pollfd * fds, nfds_t nfds, int timeout);

void (*libc_syslog) (int priority, const char *format, ...);
int (*libc_fcntl)(int fd, int cmd, ...);
int (*libc_pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void *(*start_routine) (void *), void *arg);
void (*libc_pthread_exit) (void *value_ptr);

//pid_t (*libc_vfork) (void);
//void *(*libc_dlopen)(const char *filename, int flag);
//typedef int (*openX_proto)(char const *, int, ...);
//static openX_proto libc_open = NULL;
//static openX_proto libc_open64= NULL;

int isSocket (int fd)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof (addr);
    memset (&addr, 0, sizeof(addr));
    return getsockname (fd, (struct sockaddr *) &addr, &len) == 0;
}

#define DEFAULT_LOG_FD 2     // STDERR
int __debug_log_fd = DEFAULT_LOG_FD;
int __debug_log_fd_to_use = -1;
static pthread_mutex_t init_log_lock = PTHREAD_MUTEX_INITIALIZER;
static void init_file_sock_log (const char *file_sock_path)
{
    pthread_mutex_lock (&init_log_lock);
    if (__debug_log_fd != DEFAULT_LOG_FD)
        goto EXIT;

    __debug_log_fd = libc_socket (AF_FILE, SOCK_DGRAM, 0);
    if (__debug_log_fd < 0) {
        logerr ("Cannot create socket.\n");
        goto EXIT;
    }
    if (__debug_log_fd_to_use >= 0) {
        if (libc_dup2(__debug_log_fd, __debug_log_fd_to_use) != __debug_log_fd_to_use) {
            libc_close (__debug_log_fd);
            logerr ("Cannot set debug log fd to %d\n", __debug_log_fd_to_use);
            goto EXIT;
        }
        __debug_log_fd = __debug_log_fd_to_use;
    }
    else if (__debug_log_fd == DEFAULT_LOG_FD) {
        int fd = libc_dup (__debug_log_fd);
        libc_close (__debug_log_fd);
        if (fd < 0) {
            logerr ("dup() error\n");
            __debug_log_fd = -1;
            goto EXIT;
        }
        __debug_log_fd = fd;
    }

    if (fcntl (__debug_log_fd, F_SETFD, FD_CLOEXEC) != 0) {
        logerr ("ERROR: cannot set FD_CLOEXEC on socket");
        libc_close (__debug_log_fd);
        __debug_log_fd = -1;
        goto EXIT;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_FILE;
    strncpy (addr.sun_path, file_sock_path, sizeof (addr.sun_path));
    if (libc_connect (__debug_log_fd, (struct sockaddr *) &addr, sizeof (addr)) != 0) {
        logerr ("ERROR: cannot connect to %s\n", file_sock_path);
        libc_close (__debug_log_fd);
        __debug_log_fd = -1;
    }

    EXIT:
    pthread_mutex_unlock (&init_log_lock);
}

void __debug_print (const char *buf)
{
    if (TRACE_LOG_MEDIA == SYSLOG) {
        libc_syslog (LOG_INFO, "%s", buf);
        return;
    }

    int err = 0;
RETRY:
    if (TRACE_LOG_MEDIA == VLOG) {
        if (__debug_log_fd == DEFAULT_LOG_FD) init_file_sock_log ("/tmp/vpath.log.sock");
        if (__debug_log_fd < 0) return;
    }

    int len = strlen (buf);
    const char *p = buf;
    while (len > 0) {
        int r = libc_write (__debug_log_fd, p, len);
        if (r < 0) {
            if (err > 0) return;

            // Retry on first error, because the application (e.g., ssh) may close all
            // files, including AppCloak debugging log. Retry will open it again.
            __debug_log_fd = DEFAULT_LOG_FD;
            err++;
            goto RETRY;
        }
        p += r;
        len -= r;
    }
}

static const char *
errString (int err)
{
    switch (err) {
        case EPERM: return " EPERM";
        case ENOENT: return " ENOENT";
        case ESRCH: return " ESRCH";
        case EINTR: return " EINTR";;
        case EIO: return " EIO";
        case ENXIO: return " ENXIO";
        case E2BIG: return " E2BIG";;
        case ENOEXEC: return " ENOEXEC";
        case EBADF: return " EBADF";
        case ECHILD: return " ECHILD";
        case EAGAIN: return " EAGAIN";
        case ENOMEM: return " ENOMEM";
        case EACCES: return " EACCES";
        case EFAULT: return " EFAULT";
        case ENOTBLK: return " ENOTBLK";
        case EBUSY: return " EBUSY";
        case EEXIST: return " EEXIST";
        case EXDEV: return " EXDEV";
        case ENODEV: return " ENODEV";
        case ENOTDIR: return " ENOTDIR";
        case EISDIR: return " EISDIR";
        case EINVAL: return " EINVAL";
        case ENFILE: return " ENFILE";
        case EMFILE: return " EMFILE";
        case ENOTTY: return " ENOTTY";
        case ETXTBSY: return " ETXTBSY";
        case EFBIG: return " EFBIG";
        case ENOSPC: return " ENOSPC";
        case ESPIPE: return " ESPIPE";
        case EROFS: return " EROFS";
        case EMLINK: return " EMLINK";
        case EPIPE: return " EPIPE";
        case EDOM: return " EDOM";
        case ERANGE: return " ERANGE";
        case EDEADLK: return " EDEADLK";
        case ENAMETOOLONG: return " ENAMETOOLONG";
        case ENOLCK: return " ENOLCK";
        case ENOSYS: return " ENOSYS";
        case ENOTEMPTY: return " ENOTEMPTY";
        case ELOOP: return " ELOOP";
        case ENOMSG: return " ENOMSG";
        case EIDRM: return " EIDRM";
        case ECHRNG: return " ECHRNG";
        case EL2NSYNC: return " EL2NSYNC";
        case EL3HLT: return " EL3HLT";
        case EL3RST: return " EL3RST";
        case ELNRNG: return " ELNRNG";
        case EUNATCH: return " EUNATCH";
        case ENOCSI: return " ENOCSI";
        case EL2HLT: return " EL2HLT";
        case EBADE: return " EBADE";
        case EBADR: return " EBADR";
        case EXFULL: return " EXFULL";
        case ENOANO: return " ENOANO";
        case EBADRQC: return " EBADRQC";
        case EBADSLT: return " EBADSLT";
        case EBFONT: return " EBFONT";
        case ENOSTR: return " ENOSTR";
        case ENODATA: return " ENODATA";
        case ETIME: return " ETIME";
        case ENOSR: return " ENOSR";
        case ENONET: return " ENONET";
        case ENOPKG: return " ENOPKG";
        case EREMOTE: return " EREMOTE";
        case ENOLINK: return " ENOLINK";
        case EADV: return " EADV";
        case ESRMNT: return " ESRMNT";
        case ECOMM: return " ECOMM";
        case EPROTO: return " EPROTO";
        case EMULTIHOP: return " EMULTIHOP";
        case EDOTDOT: return " EDOTDOT";
        case EBADMSG: return " EBADMSG";
        case EOVERFLOW: return " EOVERFLOW";
        case ENOTUNIQ: return " ENOTUNIQ";
        case EBADFD: return " EBADFD";
        case EREMCHG: return " EREMCHG";
        case ELIBACC: return " ELIBACC";
        case ELIBBAD: return " ELIBBAD";
        case ELIBSCN: return " ELIBSCN";
        case ELIBMAX: return " ELIBMAX";
        case ELIBEXEC: return " ELIBEXEC";
        case EILSEQ: return " EILSEQ";
        case ERESTART: return " ERESTART";
        case ESTRPIPE: return " ESTRPIPE";
        case EUSERS: return " EUSERS";
        case ENOTSOCK: return " ENOTSOCK";
        case EDESTADDRREQ: return " EDESTADDRREQ";
        case EMSGSIZE: return " EMSGSIZE";
        case EPROTOTYPE: return " EPROTOTYPE";
        case ENOPROTOOPT: return " ENOPROTOOPT";
        case EPROTONOSUPPORT: return " EPROTONOSUPPORT";
        case ESOCKTNOSUPPORT: return " ESOCKTNOSUPPORT";
        case EOPNOTSUPP: return " EOPNOTSUPP";
        case EPFNOSUPPORT: return " EPFNOSUPPORT";
        case EAFNOSUPPORT: return " EAFNOSUPPORT";
        case EADDRINUSE: return " EADDRINUSE";
        case EADDRNOTAVAIL: return " EADDRNOTAVAIL";
        case ENETDOWN: return " ENETDOWN";
        case ENETUNREACH: return " ENETUNREACH";
        case ENETRESET: return " ENETRESET";
        case ECONNABORTED: return " ECONNABORTED";
        case ECONNRESET: return " ECONNRESET";
        case ENOBUFS: return " ENOBUFS";
        case EISCONN: return " EISCONN";
        case ENOTCONN: return " ENOTCONN";
        case ESHUTDOWN: return " ESHUTDOWN";
        case ETOOMANYREFS: return " ETOOMANYREFS";
        case ETIMEDOUT: return " ETIMEDOUT";
        case ECONNREFUSED: return " ECONNREFUSED";
        case EHOSTDOWN: return " EHOSTDOWN";
        case EHOSTUNREACH: return " EHOSTUNREACH";
        case EALREADY: return " EALREADY";
        case EINPROGRESS: return " EINPROGRESS";
        case ESTALE: return " ESTALE";
        case EUCLEAN: return " EUCLEAN";
        case ENOTNAM: return " ENOTNAM";
        case ENAVAIL: return " ENAVAIL";
        case EISNAM: return " EISNAM";
        case EREMOTEIO: return " EREMOTEIO";
        case EDQUOT: return " EDQUOT";
        case ENOMEDIUM: return " ENOMEDIUM";
        case EMEDIUMTYPE: return " EMEDIUMTYPE";
        case ECANCELED: return " ECANCELED";
        case ENOKEY: return " ENOKEY";
        case EKEYEXPIRED: return " EKEYEXPIRED";
        case EKEYREVOKED: return " EKEYREVOKED";
        case EKEYREJECTED: return " EKEYREJECTED";
        default: return " err-unknown";
    }
}

static inline const char *sockTypeString (int sockType)
{
    switch (sockType) {
        case SOCK_STREAM: return "SOCK_STREAM";
        case SOCK_DGRAM: return "SOCK_DGRAM";
        case SOCK_RAW: return "SOCK_RAW";
        case SOCK_RDM: return "SOCK_RDM";
        case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
        case SOCK_PACKET: return "SOCK_PACKET";
        default: return "SOCK_unknown";
    }
}

/*
static const char *protocolString (int protocol)
{
    switch (protocol) {
        case IPPROTO_IP: return "IPPROTO_IP";
        case IPPROTO_ICMP: return "IPPROTO_ICMP";
        case IPPROTO_IGMP: return "IPPROTO_IGMP";
        case IPPROTO_IPIP: return "IPPROTO_IPIP";
        case IPPROTO_TCP: return "IPPROTO_TCP";
        case IPPROTO_EGP: return "IPPROTO_EGP";
        case IPPROTO_PUP: return "IPPROTO_PUP";
        case IPPROTO_UDP: return "IPPROTO_UDP";
        case IPPROTO_IDP: return "IPPROTO_IDP";
        case IPPROTO_RSVP: return "IPPROTO_RSVP";
        case IPPROTO_GRE: return "IPPROTO_GRE";
        case IPPROTO_IPV6: return "IPPROTO_IPV6";
        case IPPROTO_ESP: return "IPPROTO_ESP";
        case IPPROTO_AH: return "IPPROTO_AH";
        case IPPROTO_PIM: return "IPPROTO_PIM";
        case IPPROTO_COMP: return "IPPROTO_COMP";
        case IPPROTO_SCTP: return "IPPROTO_SCTP";
        case IPPROTO_RAW: return "IPPROTO_RAW";
        case IPPROTO_MAX: return "IPPROTO_MAX";
        default: return "protocol_unknown";
    }
}
*/

const char *afString (int addrFamily)
{
    switch (addrFamily) {
        case AF_UNSPEC: return "AF_UNSPEC";
        case AF_FILE: return "AF_FILE";
        case AF_INET: return "AF_INET";
        case AF_AX25: return "AF_AX25";
        case AF_IPX: return "AF_IPX";
        case AF_APPLETALK: return "AF_APPLETALK";
        case AF_NETROM: return "AF_NETROM";
        case AF_BRIDGE: return "AF_BRIDGE";
        case AF_ATMPVC: return "AF_ATMPVC";
        case AF_X25: return "AF_X25";
        case AF_INET6: return "AF_INET6";
        case AF_ROSE: return "AF_ROSE";
        case AF_DECnet: return "AF_DECnet";
        case AF_NETBEUI: return "AF_NETBEUI";
        case AF_SECURITY: return "AF_SECURITY";
        case AF_KEY: return "AF_KEY";
        case AF_NETLINK: return "AF_NETLINK";
        case AF_PACKET: return "AF_PACKET";
        case AF_ASH: return "AF_ASH";
        case AF_ECONET: return "AF_ECONET";
        case AF_ATMSVC: return "AF_ATMSVC";
        case AF_SNA: return "AF_SNA";
        case AF_IRDA: return "AF_IRDA";
        case AF_PPPOX: return "AF_PPPOX";
        case AF_WANPIPE: return "AF_WANPIPE";
        case AF_BLUETOOTH: return "AF_BLUETOOTH";
        case AF_MAX: return "AF_MAX";
        default: return "AF_unknown";
    }
}

int printData (char *p, int printLimit, char *buf, int len)
{
    int n=0, m=0;
    if (printLimit <= 0 || len <=0) return 0;

    for (n = 0; n < len; n++) {
        if (m+2 >= printLimit) break;

        if (buf[n] == '\r') {
            p[m] = '\\';
            p[m+1] = 'r';
            m += 2;
        }
        else if (buf[n] == '\n') {
            p[m] = '\\';
            p[m+1] = 'n';
            m += 2;
        }
        else if (buf[n] == '\t') {
            p[m] = '\\';
            p[m+1] = 't';
            m += 2;
        }
        else {
            p[m] = isPrintableChar (buf[n]) ? buf[n] : '.';
            m++;
        }
    }

    p[m] = 0;
    return m;
}

int printAddr (char *buf, int printLimit, const struct sockaddr * ap, socklen_t addrlen)
{
    if (ap == NULL) {
        buf[0] = '.';
        buf[1] = 0;
        return 1;
    }

    if (ap->sa_family == AF_INET) {
        if (addrlen < sizeof (struct sockaddr_in)) return snprintf (buf, printLimit, "%s", afString (ap->sa_family));

        char addr[256];
        addr[0] = 0;                              // Set string to null in case that inet_ntop fails.
        struct sockaddr_in *r = (struct sockaddr_in *) ap;
        inet_ntop (ap->sa_family, &r->sin_addr, addr, 256);
        return snprintf (buf, printLimit, "%s %d", addr, ntohs (r->sin_port));
    }

    if (ap->sa_family == AF_INET6) {
        if (addrlen < sizeof (struct sockaddr_in6)) return snprintf (buf, printLimit, "%s", afString (ap->sa_family));

        char addr[256];
        addr[0] = 0; // Set string to null in case that inet_ntop fails.
        struct sockaddr_in6 *r = (struct sockaddr_in6 *) ap;
        inet_ntop (ap->sa_family, &r->sin6_addr, addr, 256);
        return snprintf (buf, printLimit, "%s %d", addr, ntohs (r->sin6_port));
    }

    if (ap->sa_family == AF_FILE) {
        if (addrlen <= sizeof (ap->sa_family)) return snprintf (buf, printLimit, "%s", afString (ap->sa_family));

        strncpy (buf, ((struct sockaddr_un *) ap)->sun_path, printLimit-1);
        return strlen (buf);
    }

    return snprintf (buf, printLimit, "%s", afString (ap->sa_family));
}

int printAddrWithType (char *buf, int printLimit, const struct sockaddr * ap, socklen_t addrlen)
{
    if (ap == NULL) {
        buf[0] = '.';
        buf[1] = 0;
        return 1;
    }

    if (ap->sa_family == AF_INET) {
        if (addrlen < sizeof (struct sockaddr_in)) return snprintf (buf, printLimit, "%s", afString (ap->sa_family));

        char addr[256];
        addr[0] = 0;                              // Set string to null in case that inet_ntop fails.
        struct sockaddr_in *r = (struct sockaddr_in *) ap;
        inet_ntop (ap->sa_family, &r->sin_addr, addr, 256);
        return snprintf (buf, printLimit, "%s %s %d", afString(ap->sa_family), addr, ntohs (r->sin_port));
    }

    if (ap->sa_family == AF_INET6) {
        if (addrlen < sizeof (struct sockaddr_in6)) return snprintf (buf, printLimit, "%s", afString (ap->sa_family));

        char addr[256];
        addr[0] = 0; // Set string to null in case that inet_ntop fails.
        struct sockaddr_in6 *r = (struct sockaddr_in6 *) ap;
        inet_ntop (ap->sa_family, &r->sin6_addr, addr, 256);
        return snprintf (buf, printLimit, "%s %s %d", afString(ap->sa_family), addr, ntohs (r->sin6_port));
    }

    if (ap->sa_family == AF_FILE) {
        if (addrlen <= sizeof (ap->sa_family)) return snprintf (buf, printLimit, "%s", afString (ap->sa_family));
        strncpy (buf, ((struct sockaddr_un *) ap)->sun_path, printLimit-1);
        return strlen (buf);
    }

    return snprintf (buf, printLimit, "%s", afString (ap->sa_family));
}

int printLocalAddr (char *buf, int printLimit, int fd)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof (addr);

    if (getsockname (fd, (struct sockaddr *) &addr, &len) != 0) {
                sprintf(buf,"0.0.0.0 0");
        buf[9] = 0;
        return 9;
    }

    return printAddrWithType (buf, printLimit, (struct sockaddr *) & addr, len);
}

int printRemoteAddr (char *buf, int printLimit, int fd)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof (addr);

    if (getpeername (fd, (struct sockaddr *) &addr, &len) != 0) {
                sprintf(buf,"0.0.0.0 0");
        buf[9] = 0;
        return 9;
    }

    return printAddr (buf, printLimit, (struct sockaddr *) & addr, len);
}

static void
init_progname ()
{
	int i;
	for (i = 0; i < PROGNAME_LEN - 2; i++) {
		if (__progname[i] == 0) break;
		progName[i] = __progname[i];
	}

	progName[PROGNAME_LEN - 1] = 0;

        // TODO: check if platform is LINUX. AIX doesn't have /proc.
	if (!strncmp("python", progName, 6)) {
		int fd;
		char fname[PATH_MAX];
		char line[PATH_MAX];
		char *newprog;
		sprintf(fname,"/proc/%d/cmdline",getpid());
		fd = libc_open(fname,O_RDONLY);
		if (fd>=3) {
			libc_read(fd, line, PATH_MAX);
			libc_close(fd);
			while (line[i]!='\0') i++;
			newprog = line + i + 1;
			newprog = newprog + strlen(newprog) - 1;
			while (newprog[0]!='/') newprog--;
			newprog++;
			snprintf(progName,PROGNAME_LEN,"%s",newprog);
		}
	}

	if (gethostname(hname, HOSTNAME_LEN)<0)
		memcpy(hname, "unknown", HOSTNAME_LEN);
};

static int findUnusedFD (int fd)
{
	int i;
	for (i = 0; i < 500; i++) {
		if (libc_fcntl (fd, F_GETFD) == -1) return fd;
		fd++;
	}

	return -1;        // Did not find an unused fd.
}

void __attribute__((constructor)) bluecoat_init(void)
{
	//syslog(LOG_INFO, "bluecoat_init() pid:%d LD_PRELOAD:%s \n", getpid(), getenv("LD_PRELOAD"));

	//libc_dlopen = dlsym(RTLD_NEXT, "dlopen");
	libc_write = dlsym(RTLD_NEXT, "write");
	libc_writev = dlsym(RTLD_NEXT, "writev");
	libc_send = dlsym(RTLD_NEXT, "send");
	libc_sendto = dlsym(RTLD_NEXT, "sendto");
	libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
	libc_sendfile = dlsym(RTLD_NEXT, "sendfile");
	libc_fwrite = dlsym(RTLD_NEXT, "fwrite");
	libc_pwrite = dlsym(RTLD_NEXT, "pwrite");
	libc_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
	libc_pwritev = dlsym(RTLD_NEXT, "pwritev");
	libc_read = dlsym(RTLD_NEXT, "read");
	libc_readv = dlsym(RTLD_NEXT, "readv");
	libc_recv = dlsym(RTLD_NEXT, "recv");
	libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
	libc_fread = dlsym(RTLD_NEXT, "fread");
	libc_pread = dlsym(RTLD_NEXT, "pread");
	libc_pread64 = dlsym(RTLD_NEXT, "pread64");
	libc_preadv = dlsym(RTLD_NEXT, "preadv");
	libc_fork = dlsym(RTLD_NEXT, "fork");
	libc_socket = dlsym(RTLD_NEXT, "socket");
	libc_bind = dlsym(RTLD_NEXT, "bind");
	libc_accept = dlsym(RTLD_NEXT, "accept");
	libc_connect = dlsym(RTLD_NEXT, "connect");
	libc_open = dlsym(RTLD_NEXT, "open");
	libc_open64 = dlsym(RTLD_NEXT, "open64");
	libc_close = dlsym(RTLD_NEXT, "close");
	libc_dup = dlsym(RTLD_NEXT, "dup");
	libc_dup2 = dlsym(RTLD_NEXT, "dup2");
	libc_execve = dlsym(RTLD_NEXT, "execve");
	libc_execvp = dlsym(RTLD_NEXT, "execvp");
	libc_execv = dlsym(RTLD_NEXT, "execv");
	libc_execle = dlsym(RTLD_NEXT, "execle");
	libc_execlp = dlsym(RTLD_NEXT, "execlp");
	libc_execl = dlsym(RTLD_NEXT, "execl");
	libc_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
	libc_epoll_pwait = dlsym(RTLD_NEXT, "epoll_pwait");
	libc_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
	libc_epoll_create = dlsym(RTLD_NEXT, "epoll_create");
	libc_epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");
	libc_select = dlsym(RTLD_NEXT, "select");
	libc_pselect = dlsym(RTLD_NEXT, "pselect");
	libc_ppoll = dlsym(RTLD_NEXT, "ppoll");
	libc_poll = dlsym(RTLD_NEXT, "poll");
	libc_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
	libc_pthread_exit = dlsym(RTLD_NEXT, "pthread_exit");
	libc_syslog = dlsym(RTLD_NEXT, "syslog");
	libc_fcntl = dlsym(RTLD_NEXT, "fcntl");

	init_progname();
	setlogmask (LOG_UPTO (LOG_INFO));
	openlog ("bluecoat", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	__debug_log_fd_to_use = findUnusedFD (DEBUG_LOG_FD);
}

void __attribute__((destructor)) bluecoat_fini(void)
{
	//dbg("bluecoat_fini() pid:%d LD_PRELOAD:%s \n", getpid(), getenv("LD_PRELOAD"));
}

/*
static int openX(openX_proto func, char const *pathname, int flags, va_list ap)
{
	if (flags & O_RDWR) {
		flags &= ~O_RDWR;
		flags |= O_RDONLY;
	} else if (flags & O_WRONLY) {
		flags &= ~O_WRONLY;
	}
	return func(pathname, flags, va_arg(ap, mode_t));
}

int open(char const *pathname, int flags, ...)
{
	//fprintf(stderr, "open()       pid:%d LD_PRELOAD:%s \n", getpid(), getenv("LD_PRELOAD")); fflush(stderr);
	syslog(LOG_INFO, "open()       pid:%d LD_PRELOAD:%s \n", getpid(), getenv("LD_PRELOAD"));
	va_list ap;
	va_start(ap, flags);
	int ret = openX(libc_open, pathname, flags, ap);
	va_end(ap);
	return ret;
}

int open64(char const *pathname, int flags, ...)
{
	//fprintf(stderr, "open64()\n"); fflush(stderr);
	va_list ap;
	va_start(ap, flags);
	int ret = openX(libc_open64, pathname, flags, ap);
	va_end(ap);
	return ret;
}

void *dlopen(const char *filename, int flag)
{
	syslog(LOG_INFO, "dlopen()      pid:%d LD_PRELOAD:%s \n", getpid(), getenv("LD_PRELOAD"));
	flag &= (~RTLD_DEEPBIND);
	return libc_dlopen (filename, flag);
}

*/

ssize_t write(int fd, const void *buf, size_t nbyte) {
	// TODO: febootstrap-s generates too many events. So, I ignore them.
	if (!strncmp(progName,"febootstrap-s",13)) return libc_write(fd, buf, nbyte);

	SET_START_TIME();
	ssize_t ret = (*libc_write)(fd, buf, nbyte);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "write %ld %d ", ret, fd);
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
        return ret;
}

ssize_t writev(int fd, const struct iovec * iov, int iovcnt) {
	// TODO: febootstrap-s generates too many events. So, I ignore them.
	if (!strncmp(progName,"febootstrap-s",13)) return libc_writev (fd, iov, iovcnt);

	SET_START_TIME();
	int i = 0;
	ssize_t ret = libc_writev (fd, iov, iovcnt);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "writev %ld %d ", ret, fd);
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0 && iov != NULL && iovcnt > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		int left = ret;
		for (i = 0; i < iovcnt; i++) {
			int l = MIN (left, (int) iov[i].iov_len);
			p += printData (p, PRINT_LIMIT, (char *) iov[i].iov_base, l);
			left -= l;
			if (left <= 0) break;
		}
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
	SET_START_TIME();
	ssize_t ret = libc_send (fd, buf, len, flags);
	int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "send %ld %d ", ret, fd);
	p += printLocalAddr (p, PRINT_LIMIT, fd);
	p += snprintf (p, PRINT_LIMIT, " ");
	p += printRemoteAddr (p, PRINT_LIMIT, fd);
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr * to, socklen_t tolen) {
	SET_START_TIME();
	const ssize_t ret = libc_sendto (fd, buf, len, flags, to, tolen);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "sendto %ld %d ", ret, fd);
	p += printLocalAddr (p, PRINT_LIMIT, fd);
	p += snprintf (p, PRINT_LIMIT, " ");
	if (to == NULL) p += printRemoteAddr (p, PRINT_LIMIT, fd);
	else p += printAddr (p, PRINT_LIMIT, to, tolen);
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t sendmsg(int fd, const struct msghdr * msg, int flags) {
	SET_START_TIME();
	const ssize_t ret = libc_sendmsg (fd, msg, flags);
	const int save_errno = errno;
	SET_END_TIME();
	int i = 0;

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "sendmsg %ld %d ", ret, fd);
	if (msg == NULL) {
		p += snprintf (p, PRINT_LIMIT, "null");
	}
	else {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		if (msg->msg_name == NULL) p += printRemoteAddr (p, PRINT_LIMIT, fd);
		else p += printAddr (p, PRINT_LIMIT, (struct sockaddr *) msg->msg_name, msg->msg_namelen);
	}
	if (ret > 0 && msg != NULL && msg->msg_iovlen > 0 && msg->msg_iov != NULL) {
		p += snprintf (p, PRINT_LIMIT, " ");
		int left = ret;
		for (i = 0; i < (int) msg->msg_iovlen; i++) {
			int l = MIN (left, (int) msg->msg_iov[i].iov_len);
			p += printData (p, PRINT_LIMIT, (char *) msg->msg_iov[i].iov_base, l);
			left -= l;
			if (left <= 0) break;
		}
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t sendfile(int out_fd, int in_fd, off_t * offset, size_t count) {
	SET_START_TIME();
	const ssize_t ret = libc_sendfile (out_fd, in_fd, offset, count);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "sendfile %ld %d %d ", ret, out_fd, in_fd);
	p += printLocalAddr (p, PRINT_LIMIT, out_fd);
	p += snprintf (p, PRINT_LIMIT, " ");
	p += printRemoteAddr (p, PRINT_LIMIT, out_fd);
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	SET_START_TIME();
	const size_t ret = libc_fwrite(ptr, size, nmemb, stream);
	const int save_errno = errno;
	SET_END_TIME();
	const int fd = fileno(stream);

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "fwrite %ld %d ", ret*size, fd); //
	p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *)ptr, ret*size);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t nbyte, off_t offset) {

	SET_START_TIME();
	const ssize_t ret = libc_pwrite (fd, buf, nbyte, offset);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "pwrite %ld %d ", ret, fd);
	// TODO - pwrite is used for only files, not socket, consider removing isSocket
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
        return ret;
}

ssize_t pwrite64(int fd, const void *buf, size_t nbyte, off64_t offset) {

	SET_START_TIME();
	const ssize_t ret = libc_pwrite64 (fd, buf, nbyte, offset);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "pwrite64 %ld %d ", ret, fd);
	// TODO - pwrite is used for only files, not socket, consider removing isSocket
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
        return ret;
}

ssize_t pwritev(int fd, const struct iovec * iov, int iovcnt, off_t offset) {
	SET_START_TIME();
	int i = 0;
	ssize_t ret = libc_pwritev (fd, iov, iovcnt, offset);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "pwritev %ld %d ", ret, fd);
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0 && iov != NULL && iovcnt > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		int left = ret;
		for (i = 0; i < iovcnt; i++) {
			int l = MIN (left, (int) iov[i].iov_len);
			p += printData (p, PRINT_LIMIT, (char *) iov[i].iov_base, l);
			left -= l;
			if (left <= 0) break;
		}
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t read(int fd, void *buf, size_t nbyte) {
	// TODO: febootstrap-s generates too many events. So, I ignore them.
        if (!strncmp(progName,"febootstrap-s",13)) return (*libc_read)(fd, buf, nbyte);

	SET_START_TIME();
	ssize_t ret = (*libc_read)(fd, buf, nbyte);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "read %ld %d ", ret, fd);
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret> 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t readv(int fd, const struct iovec * iov, int iovcnt) {
        // TODO: febootstrap-s generates too many events. So, I ignore them.
        if (!strncmp(progName,"febootstrap-s",13)) return libc_readv (fd, iov, iovcnt);

	SET_START_TIME();
	ssize_t ret = libc_readv (fd, iov, iovcnt);
	const int save_errno = errno;
	SET_END_TIME();
	int i = 0;

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "readv %ld %d ", ret, fd);
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0 && iov != NULL && iovcnt > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		int left = ret;
		for (i = 0; i < iovcnt; i++) {
			int l = MIN (left, (int) iov[i].iov_len);
			p += printData (p, PRINT_LIMIT, (char *) iov[i].iov_base, l);
			left -= l;
			if (left <= 0) break;
		}
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
	SET_START_TIME();
	const ssize_t ret = libc_recv (fd, buf, len, flags);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "recv %ld %d ", ret, fd);
	p += printLocalAddr (p, PRINT_LIMIT, fd);
	p += snprintf (p, PRINT_LIMIT, " ");
	p += printRemoteAddr (p, PRINT_LIMIT, fd);
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr * from, socklen_t * fromlen) {
	SET_START_TIME();
	const ssize_t ret = libc_recvfrom(fd, buf, len, flags, from, fromlen);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "recvfrom %ld %d ", ret, fd);
	p += printLocalAddr (p, PRINT_LIMIT, fd);
	p += snprintf (p, PRINT_LIMIT, " ");
	if (from == NULL) p += printRemoteAddr (p, PRINT_LIMIT, fd);
	else p += printAddr (p, PRINT_LIMIT, from, fromlen == NULL ? 0 : *fromlen);
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t recvmsg(int fd, struct msghdr * msg, int flags) {
	SET_START_TIME();
	ssize_t ret = libc_recvmsg (fd, msg, flags);
	const int save_errno = errno;
	SET_END_TIME();
	int i = 0;

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "recvmsg %ld %d ", ret, fd);
	if (msg == NULL) {
		p += snprintf (p, PRINT_LIMIT, "null");
	}
	else {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		if (msg->msg_name == NULL) p += printRemoteAddr (p, PRINT_LIMIT, fd);
		else p += printAddr (p, PRINT_LIMIT, (struct sockaddr *) msg->msg_name, msg->msg_namelen);
	}
	if (ret > 0 && msg != NULL && msg->msg_iovlen > 0 && msg->msg_iov != NULL) {
		p += snprintf (p, PRINT_LIMIT, " ");
		int left = ret;
		for (i = 0; i < (int) msg->msg_iovlen; i++) {
			int l = MIN (left, (int) msg->msg_iov[i].iov_len);
			p += printData (p, PRINT_LIMIT, (char *) msg->msg_iov[i].iov_base, l);
			left -= l;
			if (left <= 0) break;
		}
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

/*
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	SET_START_TIME();
	const size_t ret = libc_fread(ptr, size, nmemb, stream);
	const int save_errno = errno;
	SET_END_TIME();
	const int fd = fileno(stream);

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "fread %ld %d ", ret*size, fd);
	p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *)ptr, ret*size);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

ssize_t pread(int fd, void *buf, size_t nbyte, off_t offset) {
	SET_START_TIME();
	ssize_t ret = (*libc_pread)(fd, buf, nbyte, offset);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "pread %ld %d ", ret, fd);
	// TODO - pread is used for only files, not socket, consider removing isSocket
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret> 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t pread64(int fd, void *buf, size_t nbyte, off64_t offset) {
	SET_START_TIME();
	ssize_t ret = (*libc_pread64)(fd, buf, nbyte, offset);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "pread64 %ld %d ", ret, fd);
	// TODO - pread is used for only files, not socket, consider removing isSocket
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret> 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printData (p, PRINT_LIMIT, (char *) buf, ret);
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}

ssize_t preadv(int fd, const struct iovec * iov, int iovcnt, off_t offset) {
	SET_START_TIME();
	ssize_t ret = libc_preadv (fd, iov, iovcnt, offset);
	const int save_errno = errno;
	SET_END_TIME();
	int i = 0;

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "preadv %ld %d ", ret, fd);
	if (isSocket(fd)) {
		p += printLocalAddr (p, PRINT_LIMIT, fd);
		p += snprintf (p, PRINT_LIMIT, " ");
		p += printRemoteAddr (p, PRINT_LIMIT, fd);
	}
	else
		p += snprintf (p, PRINT_LIMIT, "NON_SOCKET");
	if (ret > 0 && iov != NULL && iovcnt > 0) {
		p += snprintf (p, PRINT_LIMIT, " ");
		int left = ret;
		for (i = 0; i < iovcnt; i++) {
			int l = MIN (left, (int) iov[i].iov_len);
			p += printData (p, PRINT_LIMIT, (char *) iov[i].iov_base, l);
			left -= l;
			if (left <= 0) break;
		}
	}
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);
	errno = save_errno;
	return ret;
}
*/

pid_t fork () {
	SET_START_TIME();
	pid_t pid = libc_fork ();
	const int save_errno = errno;
	SET_END_TIME();

	dbg("fork %d %d %d", pid, getpid(), getppid());
	errno = save_errno;
	return pid;
}

/*
int socket (int domain, int type, int protocol) {
	SET_START_TIME();
	int fd = libc_socket (domain, type, protocol);
	const int save_errno = errno;
	SET_END_TIME();

	if (isManagedSockDomain(domain))
		dbg("socket %d %s %s %s", fd, afString (domain), sockTypeString (type), protocolString (protocol));
	errno = save_errno;
	return fd;
}

int bind (int fd, const struct sockaddr * my_addr, socklen_t addrlen) {
	SET_START_TIME();
	const int ret = libc_bind (fd, my_addr, addrlen);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	if ((my_addr->sa_family == AF_INET) || (my_addr->sa_family == AF_INET6)) {
		p += snprintf (p, PRINT_LIMIT, "bind %d %d ", ret, fd);
		if (my_addr == NULL) *p++ = '.';
		else p += printAddrWithType (p, PRINT_LIMIT, my_addr, addrlen);
		if (ret<0)
			p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	}
	else if (my_addr->sa_family == AF_FILE) {
		struct sockaddr_un *addr = (struct sockaddr_un *) my_addr;
		const int l = (addrlen <= sizeof (sa_family_t)) ? 0 : strlen (addr->sun_path);
		p += snprintf (p, PRINT_LIMIT, "bind %d %d %s ", ret, fd, afString(my_addr->sa_family));
		if (l>0) {
			p += printData(p, PRINT_LIMIT, (char*)(addr->sun_path), l);
		}
		else
			p += snprintf (p, PRINT_LIMIT, "error");
	}
	else {
		p += snprintf (p, PRINT_LIMIT, "bind %d %d %s ", ret, fd, afString(my_addr->sa_family));
		if (ret<0)
			p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	}
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

int accept (int listenfd, struct sockaddr * remote, socklen_t * addrlen) {
	SET_START_TIME();
	int connfd = libc_accept (listenfd, remote, addrlen);
	const int save_errno = errno;
	SET_END_TIME();
	int ret;

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;

	p += snprintf (p, PRINT_LIMIT, "accept %d %d ", connfd, listenfd);
	if (connfd >= 0) p += printLocalAddr (p, PRINT_LIMIT, connfd);
	else p += printLocalAddr (p, PRINT_LIMIT, listenfd);
	p += snprintf (p, PRINT_LIMIT, " ");
	p += printRemoteAddr (p, PRINT_LIMIT, connfd);
	ret = connfd;
	if (connfd<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

    errno = save_errno;
    return connfd;
}

int connect (int fd, const struct sockaddr * serv_addr, socklen_t addrlen) {
	SET_START_TIME();
	const int ret = libc_connect (fd, serv_addr, addrlen);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "connect %d %d ", ret, fd);
	p += printLocalAddr (p, PRINT_LIMIT, fd);
	p += snprintf (p, PRINT_LIMIT, " ");
	p += printAddr (p, PRINT_LIMIT, serv_addr, addrlen);
	if (ret<0)
	p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

    errno = save_errno;
    return ret;
}

int open(const char *filename, int flags, ...) {
	int ret;
	va_list ap;
	mode_t mode;

	SET_START_TIME();
	if (flags & O_CREAT) {
		va_start (ap, flags);
		mode = va_arg (ap, mode_t);
		va_end (ap);
		ret = libc_open(filename, flags, mode);
	}
	else {
		ret = libc_open(filename, flags);
	}
	const int save_errno = errno;
	SET_END_TIME();

	dbg("open %d %s %d", ret, filename, flags);

	errno = save_errno;
	return ret;
}

int open64(const char *filename, int flags, ...) {
	int ret;
	int save_errno;
	va_list ap;
	mode_t mode;

	SET_START_TIME();
	if (flags & O_CREAT) {
		va_start (ap, flags);
		mode = va_arg (ap, mode_t);
		va_end (ap);
		ret = libc_open64(filename, flags, mode);
	}
	else {
		ret = libc_open64(filename, flags);
	}
	save_errno = errno;
	SET_END_TIME();

	dbg("open64 %d %s %d", ret, filename, flags);

	errno = save_errno;
	return ret;
}

int close (int fd) {

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	char tmpBuf1[PRINT_BUF_SIZE];
	char tmpBuf2[PRINT_BUF_SIZE];
	char *q1 = tmpBuf1;
	char *q2 = tmpBuf2;

	SET_START_TIME();
	if (isSocket(fd)) {
		q1 += printLocalAddr (q1, PRINT_LIMIT, fd);
		q1 += snprintf (q1, PRINT_LIMIT, " ");
		q1 += printRemoteAddr (q1, PRINT_LIMIT, fd);
	}
	else
		q1 += snprintf (q1, PRINT_LIMIT, "NON_SOCKET");

	const int ret = libc_close (fd);
	const int save_errno = errno;
	SET_END_TIME();

	q2 += snprintf (q2, PRINT_LIMIT, "close %d %d %s", ret, fd, tmpBuf1);
	//if (ret<0) q2 += snprintf (q2, PRINT_LIMIT, "%s", ERR_STRING);
	dbg("%s", tmpBuf2);
	errno = save_errno;
	return ret;
}

int dup (int oldfd) {
	SET_START_TIME();
	int ret = libc_dup (oldfd);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	p += snprintf (p, PRINT_LIMIT, "dup %d %d ", ret, oldfd);
	p += printLocalAddr (p, PRINT_LIMIT, oldfd);
	p += snprintf (p, PRINT_LIMIT, " ");
	p += printRemoteAddr (p, PRINT_LIMIT, oldfd);
	if (ret<0)
		p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

int dup2 (int oldfd, int newfd) {
	SET_START_TIME();
	int ret = libc_dup2 (oldfd, newfd);
	const int save_errno = errno;
	SET_END_TIME();

	int isOldfdSock = isSocket (oldfd);
	int isNewfdSock = isSocket (newfd);

	if (isOldfdSock || isNewfdSock) {
		char printBuf[PRINT_BUF_SIZE];
		char *p = printBuf;
		p += snprintf (p, PRINT_LIMIT, "dup2 %d %d %d", ret, oldfd, newfd);

		if (isOldfdSock) {
			p += printLocalAddr (p, PRINT_LIMIT, oldfd);
			p += snprintf (p, PRINT_LIMIT, " ");
			p += printRemoteAddr (p, PRINT_LIMIT, oldfd);
		}

		if (isNewfdSock) {
			p += printLocalAddr (p, PRINT_LIMIT, newfd);
			p += snprintf (p, PRINT_LIMIT, " ");
			p += printRemoteAddr (p, PRINT_LIMIT, newfd);
		}
		if (ret<0)
			p += snprintf (p, PRINT_LIMIT, " %s", ERR_STRING);
		dbg("%s", printBuf);
	}

	errno = save_errno;
	return ret;
}
*/

/*
int execve (const char *filename, char *const argv[], char *const envp[]) {
	int ret;
	SET_START_TIME();
	const char *fn = filename == NULL ? "null" : filename;
	UNUSED(fn);
	dbg("execve 0 %d %s\n", getpid(), fn);
	SET_END_TIME();
	ret = libc_execve (filename, argv, envp);
	int save_errno = errno;
	SET_END_TIME();
	dbg("execve %d (%s) failed = %d%s\n", ret, fn, ret, ERR_STRING);
	errno = save_errno;
	return ret;
}

int execle (const char *path, const char *arg, ...) {
	SET_START_TIME();
	const char *fn;

	fn = path == NULL ? "null" : path;
	SET_END_TIME();
	dbg("execle 0 %d %s\n", getpid(), fn);

#define INITIAL_ARGV_MAX 1024
	size_t argv_max = INITIAL_ARGV_MAX;
	const char *initial_argv[INITIAL_ARGV_MAX];
	const char **argv = initial_argv;
	va_list args;
	argv[0] = arg;

	va_start (args, arg);
	unsigned int i = 0;
	while (argv[i++] != NULL) {
		if (i == argv_max) {
			argv_max *= 2;
			const char **nptr = (const char **) realloc (argv == initial_argv ? NULL : argv, argv_max * sizeof (const char *));
			if (nptr == NULL) {
				if (argv != initial_argv) free (argv);
				return -1;
			}
			if (argv == initial_argv) memcpy (nptr, argv, i * sizeof (const char *)); // We have to copy the already filled-in data ourselves.
			argv = nptr;
		}
		argv[i] = va_arg (args, const char *);
	}

	const char *const *envp = va_arg (args, const char *const *);
	va_end (args);

	int ret = libc_execve (path, (char *const *) argv, (char *const *) envp);
	const int save_errno = errno;
	SET_END_TIME();

	dbg("execle %d (%s) failed = %d\n", ret, fn, ret);
	if (argv != initial_argv) free (argv);
	errno = save_errno;

	UNUSED (fn);
	return ret;
}

int execvp (const char *file, char *const argv[]) {
	SET_START_TIME();

	const char *fn = file == NULL ? "null" : file;
	SET_END_TIME();
	dbg("execvp 0 %d %s\n", getpid(), fn);

	//if (LD_PRELOAD && getenv ((char *) "LD_PRELOAD") == NULL) putenv (LD_PRELOAD);
	int ret = libc_execvp (file, argv);
	const int save_errno = errno;
	SET_END_TIME();

	dbg("execvp %d (%s) failed = %d%s\n", ret, fn, ret, ERR_STRING);

	errno = save_errno;
	UNUSED (fn);
	return ret;
}

int execv (const char *path, char *const argv[]) {
	SET_START_TIME();

	const char *fn = path == NULL ? "null" : path;
	SET_END_TIME();
	dbg("execv 0 %d %s\n", getpid(), fn);

	//if (LD_PRELOAD && getenv ((char *) "LD_PRELOAD") == NULL) putenv (LD_PRELOAD);
	int ret = libc_execv (path, argv);
	const int save_errno = errno;
	SET_END_TIME();

	dbg("execv %d (%s) failed = %d%s\n", ret, fn, ret, ERR_STRING);

	errno = save_errno;
	UNUSED (fn);
	return ret;
}

int execl (const char *path, const char *arg, ...) {
	SET_START_TIME();

	const char *fn;

	fn = path == NULL ? "null" : path;
	SET_END_TIME();
	dbg("execl 0 %d %s\n", getpid(), fn);

#define INITIAL_ARGV_MAX 1024
	size_t argv_max = INITIAL_ARGV_MAX;
	const char *initial_argv[INITIAL_ARGV_MAX];
	const char **argv = initial_argv;
	va_list args;

	argv[0] = arg;

	va_start (args, arg);
	unsigned int i = 0;
	while (argv[i++] != NULL) {
		if (i == argv_max) {
			argv_max *= 2;
			const char **nptr = (const char **) realloc (argv == initial_argv ? NULL : argv, argv_max * sizeof (const char *));
			if (nptr == NULL) {
				if (argv != initial_argv) free (argv);
				return -1;
			}
			if (argv == initial_argv) memcpy (nptr, argv, i * sizeof (const char *)); // We have to copy the already filled-in data ourselves.
			argv = nptr;
		}

		argv[i] = va_arg (args, const char *);
	}
	va_end (args);

	int ret = libc_execve (path, (char *const *) argv, environ);
	SET_END_TIME();

	const int save_errno = errno;
	dbg("execl(%s) failed = %d\n", fn, ret);
	if (argv != initial_argv) free (argv);
	errno = save_errno;

	UNUSED (fn);
	return ret;
}

int execlp (const char *file, const char *arg, ...) {
	SET_START_TIME();

	const char *fn;

	fn = file == NULL ? "null" : file;
	SET_END_TIME();
	dbg("execlp 0 %d %s\n", getpid(), fn);

#define INITIAL_ARGV_MAX 1024
	size_t argv_max = INITIAL_ARGV_MAX;
	const char *initial_argv[INITIAL_ARGV_MAX];
	const char **argv = initial_argv;
	va_list args;

	argv[0] = arg;

	va_start (args, arg);
	unsigned int i = 0;
	while (argv[i++] != NULL) {
		if (i == argv_max) {
			argv_max *= 2;
			const char **nptr = (const char **) realloc (argv == initial_argv ? NULL : argv, argv_max * sizeof (const char *));
			if (nptr == NULL) {
				if (argv != initial_argv) free (argv);
				return -1;
			}
			if (argv == initial_argv) memcpy (nptr, argv, i * sizeof (const char *)); // We have to copy the already filled-in data ourselves.
			argv = nptr;
		}

		argv[i] = va_arg (args, const char *);
	}
	va_end (args);

	int ret = libc_execvp (file, (char *const *) argv);
	const int save_errno = errno;
	SET_END_TIME();

	dbg("execlp %d (%s) failed = %d\n", ret, fn, ret);
	if (argv != initial_argv) free (argv);
	errno = save_errno;

    UNUSED (fn);
    return ret;
}
*/

static inline const char *
epoll_ctl_to_string (int op)
{
    switch (op) {
        case EPOLL_CTL_ADD: return "ADD";
        case EPOLL_CTL_MOD: return "MOD";
        case EPOLL_CTL_DEL: return "DEL";
        default: return "unknown";
    }
}

static inline const char *
epoll_event_string (uint32_t event)
{
    if (event & EPOLLET) {
        if (event & EPOLLIN) {
            if (event & EPOLLOUT) return "edge-IN|OUT, ";
            else return "edge-IN, ";
        }

        if (event & EPOLLOUT) return "edge-OUT, ";
        else return "";
    }
    else {
        if (event & EPOLLIN) {
            if (event & EPOLLOUT) return "level-IN|OUT, ";
            else return "level-IN, ";
        }

        if (event & EPOLLOUT) return "level-OUT, ";
        else return "";
    }
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
	SET_START_TIME();

	int ret = libc_epoll_ctl (epfd, op, fd, event);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;
	//p += snprintf (printBuf, PRINT_BUF_SIZE, "epoll_ctl %d (epfd=%d, %s, %sfd=%d) = %d%s", ret, epfd, epoll_ctl_to_string (op),
	//	event ? epoll_event_string (event->events) : "(null)", fd, ret, ERR_STRING);
	p += snprintf (printBuf, PRINT_BUF_SIZE, "epoll_ctl %d %d %d %d", ret, epfd, op, fd);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

int epoll_pwait (int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t * sigmask) {

	// Make epoll process one event at a time
	//if (maxevents > 1) maxevents = 1;

	SET_START_TIME();
	int ret = libc_epoll_pwait (epfd, events, maxevents, timeout, sigmask);
	const int save_errno = errno;
	SET_END_TIME();

	if (ret>0) {
		char printBuf[PRINT_BUF_SIZE];
		//snprintf (printBuf, PRINT_BUF_SIZE, "epoll_pwait %d (timeout=%d) = %d%s", ret, timeout, ret, ERR_STRING);
		snprintf (printBuf, PRINT_BUF_SIZE, "epoll_pwait %d %d %d %d %d", ret, epfd, events[0].data.fd, maxevents, timeout);
		dbg("%s", printBuf);
	}
	errno = save_errno;
	return ret;
}

int epoll_wait (int epfd, struct epoll_event *events, int maxevents, int timeout) {

	// Make epoll process one event at a time
	if (maxevents > 1) maxevents = 1;

	SET_START_TIME();
	int ret = libc_epoll_wait (epfd, events, maxevents, timeout);
	const int save_errno = errno;
	SET_END_TIME();

	if (ret>0) {
		char printBuf[PRINT_BUF_SIZE];
		char *p = printBuf;
		//p += snprintf (printBuf, PRINT_BUF_SIZE, "epoll_wait %d (epfd=%d, timeout=%d) = %d%s", ret, epfd, timeout, ret, ERR_STRING);
		p += snprintf (printBuf, PRINT_BUF_SIZE, "epoll_wait %d %d %d", ret, epfd, events[0].data.fd);
		dbg("%s", printBuf);
	}
	errno = save_errno;
	return ret;
}

int epoll_create (int size) {

	SET_START_TIME();
	int ret = libc_epoll_create (size);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	//snprintf (printBuf, PRINT_BUF_SIZE, "epoll_create %d (%d) = %d%s", ret, size, ret, ERR_STRING);
	snprintf (printBuf, PRINT_BUF_SIZE, "epoll_create %d -1 %d", ret, size);
	dbg("%s", printBuf);

	errno = save_errno;
	return ret;
}

int epoll_create1 (int flag) {
	SET_START_TIME();
	int ret = libc_epoll_create1 (flag);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	//snprintf (printBuf, PRINT_BUF_SIZE, "epoll_create1 %d (%d) = %d%s", ret, flag, ret, ERR_STRING);
	snprintf (printBuf, PRINT_BUF_SIZE, "epoll_create1 %d -1 %d", ret, flag);
	dbg("%s", printBuf);
	errno = save_errno;

	return ret;
}

/*
int select (int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval *timeout) {

	SET_START_TIME();
	int ret = libc_select (nfds, readfds, writefds, exceptfds, timeout);
	const int save_errno = errno;
	SET_END_TIME();

	if (ret>0) {
		char printBuf[PRINT_BUF_SIZE];
		char *p = printBuf;
		if (timeout == NULL) p += snprintf (p, PRINT_BUF_SIZE, "select %d ([block]) = %d%s", ret, ret, ERR_STRING);
		else p += snprintf (p, PRINT_BUF_SIZE, "select %d (timeout=[%ld  %ld]) = %d%s", ret, timeout->tv_sec, timeout->tv_usec, ret, ERR_STRING);
		dbg("%s\n", printBuf);
	}
	errno = save_errno;
	return ret;
}

int pselect (int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, const struct timespec *timeout, const sigset_t * sigmask) {

	SET_START_TIME();
	int ret = libc_pselect (nfds, readfds, writefds, exceptfds, timeout, sigmask);
	const int save_errno = errno;
	SET_END_TIME();

	if (ret>0) {
		char printBuf[PRINT_BUF_SIZE];
		if (timeout == NULL) snprintf (printBuf, PRINT_BUF_SIZE, "pselect %d ([block]) = %d%s", ret, ret, ERR_STRING);
		else snprintf (printBuf, PRINT_BUF_SIZE, "pselect %d (timeout=[%ld,%ld]) = %d%s", ret, timeout->tv_sec, timeout->tv_nsec, ret, ERR_STRING);
		dbg("%s\n", printBuf);
	}
	errno = save_errno;
	return ret;
}

static inline const char *poll_event_string (uint32_t event)
{
        if (event & POLLIN) {
            if (event & POLLOUT) return "IN|OUT";
            else return "IN";
        }

        if (EPOLLOUT) return "OUT";
        else return "";
}

int poll (struct pollfd *fds, nfds_t nfds, int timeout) {
	nfds_t i = 0;
	SET_START_TIME();

	int ret = libc_poll (fds, nfds, timeout);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;

	p += snprintf (p, PRINT_LIMIT, "poll %d (", ret);
	if (fds) {
		for (i = 0; i < nfds; i++) {
			if (i == 0) p += snprintf (p, PRINT_LIMIT, "[%d-%s", fds[i].fd, poll_event_string(fds[i].events));
			else p += snprintf (p, PRINT_LIMIT, " %d-%s", fds[i].fd, poll_event_string(fds[i].events));
		}
		p += snprintf (p, PRINT_LIMIT, "], timeout=%d", timeout);
	}
	p += snprintf (p, PRINT_LIMIT, ") = %d%s", (int) ret, ERR_STRING);
	dbg("%s\n", printBuf);

	errno = save_errno;
	return ret;
}

int ppoll (struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t * sigmask) {
	nfds_t i = 0;
	SET_START_TIME();

	int ret = libc_ppoll (fds, nfds, timeout, sigmask);
	const int save_errno = errno;
	SET_END_TIME();

	char printBuf[PRINT_BUF_SIZE];
	char *p = printBuf;

	p += snprintf (p, PRINT_LIMIT, "ppoll %d (", ret);
	if (fds) {
		for (i = 0; i < nfds; i++) {
			if (i == 0) p += snprintf (p, PRINT_LIMIT, "[%d-%s", fds[i].fd, poll_event_string(fds[i].events));
			else p += snprintf (p, PRINT_LIMIT, " %d-%s", fds[i].fd, poll_event_string(fds[i].events));
		}

		if (timeout == NULL) p += snprintf (p, PRINT_LIMIT, "]");
		else p += snprintf (p, PRINT_LIMIT, "], timeout=[%ld %ld]", timeout->tv_sec, timeout->tv_nsec);
	}
	p += snprintf (p, PRINT_LIMIT, ") = %d%s", (int) ret, ERR_STRING);
	dbg("%s\n", printBuf);

	errno = save_errno;
	return ret;
}

int pthread_create (pthread_t * thread, const pthread_attr_t * attr, void *(*start_routine) (void *), void *arg) {
	SET_START_TIME();

	int ret = libc_pthread_create (thread, attr, start_routine, arg);
	const int save_errno = errno;
	SET_END_TIME();

	if (thread == NULL) dbg("pthread_create %d () = %d%s\n", ret, ret, ERR_STRING);
	else dbg("pthread_create %d (%lx) = %d%s\n", ret, (unsigned long) (*thread), ret, ERR_STRING);

	errno = save_errno;
	return ret;
}

void pthread_exit (void *value_ptr) {
	SET_START_TIME();

	dbg("%s", "pthread_exit ()");
	libc_pthread_exit (value_ptr);
}
*/
