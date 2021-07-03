#include "commonsocket.h"

int comm_socket_nonblock(int socket, int enable)
{
	if (enable)
		return fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) | O_NONBLOCK);
	else
		return fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) & ~O_NONBLOCK);
}

static unsigned comm_getBufferSize(int bufOptName,int socket) 
{
	unsigned curSize;
	socklen_t sizeSize = sizeof(curSize);
	if (getsockopt(socket, SOL_SOCKET, bufOptName,(char*)&curSize, &sizeSize) < 0) 
	{
		ERR("comm_getBufferSize() error: errno=%d\n",errno);
		return 0;
	}	
	return curSize;
}

unsigned comm_getSendBufferSize(int socket) 
{
	return comm_getBufferSize(SO_SNDBUF, socket);
}

unsigned comm_getReceiveBufferSize(int socket) 
{
	return comm_getBufferSize(SO_RCVBUF, socket);
}

static unsigned comm_setBufferTo(int bufOptName,int socket, unsigned requestedSize)
{
	int sizeSize = sizeof(requestedSize);
	setsockopt(socket, SOL_SOCKET, bufOptName, (char*)&requestedSize, sizeSize);	
	return comm_getBufferSize(bufOptName, socket);
}

unsigned comm_setSendBufferTo(int socket, unsigned requestedSize) 
{
	return comm_setBufferTo(SO_SNDBUF, socket, requestedSize);
}

unsigned comm_setReceiveBufferTo(int socket, unsigned requestedSize)
{
	return comm_setBufferTo(SO_RCVBUF, socket, requestedSize);
}

static unsigned comm_increaseBufferTo(int bufOptName, int socket, unsigned requestedSize) 
{
	int	sizeSize;
	unsigned curSize;
	curSize = comm_getBufferSize(bufOptName, socket);

	while (requestedSize > curSize) 
	{
		sizeSize = sizeof requestedSize;
		if (setsockopt(socket, SOL_SOCKET, bufOptName,
					(char*)&requestedSize, sizeSize) >= 0) 
		{
			return requestedSize;
		}
		requestedSize = (requestedSize+curSize)/2;
	}

	return comm_getBufferSize(bufOptName, socket);
}

unsigned comm_increaseSendBufferTo(int socket, unsigned requestedSize) 
{
	return comm_increaseBufferTo(SO_SNDBUF, socket, requestedSize);
}

unsigned comm_increaseReceiveBufferTo(int socket, unsigned requestedSize) 
{
	return comm_increaseBufferTo(SO_RCVBUF, socket, requestedSize);
}

int comm_isocket_creat(int af,INTF_SOCKTP socktype, int port)
{

	int		fd, i_val, ret,st;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;

	if(socktype == INTF_TCP)
	{
		st = SOCK_STREAM;
	}
	else if(socktype == INTF_UDP)
	{
		st = SOCK_DGRAM;
	}
	else
	{
		return -1;
	}
	//fd = socket(AF_INET, st, 0);
	fd = socket(af, st, 0);
	if ( fd < 0)
	{
		ERR("creat socket");
		return -1;
	}

	ret = comm_socket_nonblock( fd, 1);
	if (ret < 0)
	{
		close(fd);
		ERR("set socket noblocke");
		return -1;
	}

	i_val = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&i_val,
			sizeof( i_val ));
	if (ret < 0)
	{
		close(fd);
		ERR("set socket reuseadd");
		return -1;
	}
		
	if (af == AF_INET6)
	{
		ret = comm_make_sockAddr6((struct sockaddr_in6*)&addr6, NULL, port);
	}
	else
	{
		ret = comm_make_sockAddr((struct sockaddr_in*)&addr, NULL, port);
	}
	if( ret == 0)
	{
		close(fd);
		return -1;
	}

	if (af == AF_INET6)
	{
		ret = bind(fd, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
	}
	else
	{
		ret = bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	}
	if (ret != 0)		
	{
		close(fd);
		return -1;
	}

	return fd;
}


void comm_socket_close(int socket)
{
	if (socket < 0)
		return;
	shutdown(socket, SHUT_RDWR); // barney 2016.10.13
	close(socket);
}

int	comm_set_socket_sendBUf(int socket, int bufsize)
{
	int		ret;

	if (socket < 0)
		return 0;

	ret = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(int));
	if (ret < 0)
	{
		ERR("set socket sendBuf,errno=%d\n",errno);
		return 0;
	}

	return 1;
}

int	comm_set_socket_recvBUf(int socket, int bufsize)
{
	int		ret;

	if (socket < 0)
		return 0;

	ret = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(int));
	if (ret < 0)
	{
		ERR("set socket recvBuf,errno=%d\n",errno);
		return 0;
	}

	return 1;
}

int	comm_socket_joinGroup(int socket, struct sockaddr *addr)
{
	struct ip_mreq	mreq;

	if (socket < 0)
		return 0;

	mreq.imr_multiaddr.s_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	mreq.imr_interface.s_addr= INADDR_ANY;
	if (setsockopt(socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *)&mreq, sizeof(mreq)) < 0)
	{
		ERR("set socket joinGroup,errno=%d\n",errno);
		return 0;
	}

	return 1;
}
int	comm_socket_leaveGroup(int socket, struct sockaddr *addr)
{
	struct ip_mreq	mreq;

	if (socket < 0)
		return 0;

	mreq.imr_multiaddr.s_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	mreq.imr_interface.s_addr= INADDR_ANY;
	if (setsockopt(socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const void *)&mreq, sizeof(mreq)) < 0)
	{
		ERR("set socket leaveGroup,errno=%d\n",errno);
		return 0;
	}

	return 1;
}

char* comm_socket_getIp(int socket)
{
	struct sockaddr_in sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);

	if (0 != getsockname(socket, (struct sockaddr *)&sockAddr, &addrLen))
		return 0;
	return inet_ntoa(sockAddr.sin_addr);
}

char* comm_socket_getIp6(int socket)
{
	struct sockaddr_in6 sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);
	char ip[INET6_ADDRSTRLEN+1] = {0};
	if (0 != getsockname(socket, (struct sockaddr *)&sockAddr, &addrLen))
		return 0;
	return (char *)inet_ntop(AF_INET6, &sockAddr, ip, INET6_ADDRSTRLEN);
}
int comm_socket_getPort(int socket)
{
	struct sockaddr_in sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);

	if (0 != getsockname(socket, (struct sockaddr *)&sockAddr, &addrLen))
		return 0;
	return ntohs(sockAddr.sin_port);
}

int comm_socket_getPort6(int socket)
{
	struct sockaddr_in6 sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);
	if (0 != getsockname(socket, (struct sockaddr *)&sockAddr, &addrLen))
		return 0;
	return ntohs(sockAddr.sin6_port);
}
char* comm_socket_getPeerIp(int socket)
{
	struct sockaddr_in sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);

	if (0 != getpeername(socket, (struct sockaddr *)&sockAddr, &addrLen))
	{
		return NULL; // barney 2016.10.12
	}
	return (char *)inet_ntoa(sockAddr.sin_addr);
}
char* comm_socket_getPeerIp6(int socket)
{
	struct sockaddr_in6 sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);
	char ip[INET6_ADDRSTRLEN+1] = {0};
	if (0 != getpeername(socket, (struct sockaddr *)&sockAddr, &addrLen))
		return 0;
	return (char *)inet_ntop(AF_INET6, &sockAddr, ip, INET6_ADDRSTRLEN);
}

int comm_socket_getPeerPort(int socket)
{
	struct sockaddr_in sockAddr;
	socklen_t addrLen = sizeof(struct sockaddr);

	if (0 != getpeername(socket, (struct sockaddr *)&sockAddr, &addrLen))
		return 0;
	return ntohs(sockAddr.sin_port);
}

int	 comm_socket_badAddress(unsigned int addr) 
{
	unsigned int hAddr = ntohl(addr);
	return (hAddr == 0x7F000001 /* 127.0.0.1 */
			|| hAddr == 0
			|| hAddr == (unsigned int)(~0));
}

int comm_resolve_host(struct in_addr *sin_addr, const char *hostname)
{
	struct hostent *hp;

	if (!inet_aton(hostname, sin_addr)) 
	{
		hp = gethostbyname(hostname);
		if (!hp)
			return 0;
		memcpy(sin_addr, hp->h_addr_list[0], sizeof(struct in_addr));
		printf("hostname:%s, hostip:%s\n", hostname, inet_ntoa(*sin_addr));	
	}

	return 1;
}

int comm_resolve_host6(struct in6_addr *sin_addr, const char *hostname)
{
	struct hostent *hp;
	if (inet_pton(AF_INET6,hostname, sin_addr) <=0 ) 
	{
		hp = gethostbyname2(hostname,AF_INET6);
		if (!hp)
			return 0;
		inet_ntop(AF_INET6, (char *)hp->h_addr_list[0],(char *)&sin_addr, (size_t) hp->h_length);//IPV6
	}
	return 1;
}
int comm_make_sockAddr(struct sockaddr_in *addr, const char *hostname, int port)
{
	/* set the destination address */
	if(hostname == NULL)		
		addr->sin_addr.s_addr = INADDR_ANY;
	else if (comm_resolve_host(&(addr->sin_addr), hostname) < 0)
		return 0;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);

	return sizeof(struct sockaddr_in);
}

int comm_make_sockAddr6(struct sockaddr_in6 *addr, const char *hostname, int port)
{
	if(hostname == NULL)		
		addr->sin6_addr = in6addr_any;
	else if (comm_resolve_host6(&(addr->sin6_addr), hostname) < 0)
		return 0;
	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(port);
	return sizeof(struct sockaddr_in6);
}
int comm_sMulticastAddress(const char * szIp) 
{
	struct in_addr	sin_addr;
	unsigned int	addressInHostOrder;
	if (!inet_aton(szIp, &sin_addr)) 
		return 0;
	addressInHostOrder = ntohl(sin_addr.s_addr);
	return addressInHostOrder >  0xE00000FF && addressInHostOrder <= 0xEFFFFFFF;
}

