#ifndef _COMMONSOCKET_H_
#define _COMMONSOCKET_H_
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>


#ifndef MERGEFD
#define	MERGEFD(fd,set)	\
	do {FD_SET(fd, set); if (fd > maxfd) maxfd = fd; } while (0)
#endif

#ifndef DBG
#define DBG(fmt, args...) do { \
				 fprintf(stdout, "\033[m""[-DBG-] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	 \
			 } while(0)
#endif
			
#ifndef SUCCESS_TRACE
#define SUCCESS_TRACE(fmt, args...) do { \
				 fprintf(stdout, "\033[1;32m""[SUCCESS_TRACE!] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	\
			 } while(0)
#endif
			
#ifndef WARNING_TRACE
#define WARNING_TRACE(fmt, args...) do { \
				 fprintf(stdout, "\033[1;33m""[WARNING_TRACE!] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	\
			 } while(0)
#endif
			
#ifndef BLUE_TRACE
#define BLUE_TRACE(fmt, args...) do { \
				 fprintf(stdout, "\033[1;34m""[TRACE!] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	\
			 } while(0)
#endif
			
#ifndef MAGENTA_TRACE
#define MAGENTA_TRACE(fmt, args...) do { \
				 fprintf(stdout, "\033[1;35m""[TRACE!] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	\
			 } while(0)
#endif
			
#ifndef CYAN_TRACE
#define CYAN_TRACE(fmt, args...) do { \
				 fprintf(stdout, "\033[1;36m""[TRACE!] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	\
			 } while(0)
#endif
			
#ifndef ERR
#define ERR(fmt, args...) do { \
				 fprintf(stderr, "\033[1;31m""[ERR!] [%s:%5d] " fmt, (char *)__FILE__,__LINE__,## args);	\
			 } while(0)
#endif

typedef enum {
    INTF_TCP    = 0,
    INTF_UDP     = 1,
} INTF_SOCKTP;

typedef enum
{
	RTSP_TCP_NORMAL_SEND,
	RTSP_TCP_SEND_FAIL,
	RTSP_TCP_SOCKET_INVALID,
}RTSP_SEND_STATE;

#ifdef __cplusplus
extern "C" {
#endif

int			comm_socket_nonblock(int socket, int enable);
unsigned 	comm_increaseSendBufferTo(int socket, unsigned requestedSize);
unsigned 	comm_increaseReceiveBufferTo(int socket, unsigned requestedSize); 
unsigned 	comm_setSendBufferTo(int socket, unsigned requestedSize);
unsigned 	comm_setReceiveBufferTo(int socket, unsigned requestedSize);

int			comm_isocket_creat(int af, INTF_SOCKTP socktype, int port);
void		comm_socket_close(int socket);

int			comm_set_socket_sendBUf(int socket, int bufsize);
int			comm_set_socket_recvBUf(int socket, int bufsize);

int			comm_socket_joinGroup(int socket, struct sockaddr *addr);
int			comm_socket_leaveGroup(int socket, struct sockaddr *addr);

char		*comm_socket_getIp(int socket);
char		*comm_socket_getIp6(int socket);

int			comm_socket_getPort(int socket);
int 		comm_socket_getPort6(int socket);

char		*comm_socket_getPeerIp(int socket);
char		* comm_socket_getPeerIp6(int socket);
int			comm_socket_getPeerPort(int socket);
int			comm_socket_badAddress(unsigned int addr);

int			comm_resolve_host(struct in_addr *sin_addr, const char *hostname);
int 		comm_make_sockAddr(struct sockaddr_in *addr, const char *hostname, int port);
int 		comm_make_sockAddr6(struct sockaddr_in6 *addr, const char *hostname, int port);
int			comm_sMulticastAddress(const char * szIp);

int			comm_tcp_nobolock_connect(int af,int srcPort, const char *dstHost, int dstPort, int timeout);
int			comm_tcp_connect(int af,int srcPort, const char *dstHost, int dstPort);
int			comm_tcp_listen(int af,const char *psz_host, int i_port);
int			comm_tcp_create(int af,const char *psz_host, int i_port);
int			comm_tcp_accept(int fd, struct sockaddr *sa);
int			comm_tcp_noblock_accept(int fd, struct sockaddr *sa, int timeout);
int			comm_tcp_read(int fd, char *buf, int size, int to);
int			comm_tcp_exRead(int fd, char *buf, int size, int to);
int			comm_tcp_write(int fd, char *buf, int size, int to);
int			comm_tcp_write_packet(int fd, char *buf, int size, int maxMtu, int to);
int			comm_tcp_noblock_write(int hSock,char *pbuf,int size, int *pBlock);


int			comm_udp_socket_read(int fd, char *buf, int size, struct sockaddr *from);
int			comm_udp_socket_readEx(int fd, char *buf, int size, struct sockaddr *from);
int			comm_udp_write(int fd, char *buf, int size, struct sockaddr *to);
int			comm_udp_write_Packet(int fd, char *buf, int size, int maxMtu, struct sockaddr *to);

#ifdef __cplusplus
}
#endif

#endif
