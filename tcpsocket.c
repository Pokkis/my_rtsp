 #include "commonsocket.h"
 #include "rtsphead.h"

static int g_RtspSocket = -1;
int comm_tcp_nobolock_connect(int af, int srcPort, const char *dstHost, int dstPort, int timeout)
{
	struct timeval tv;
	fd_set	wfds;
    int	ret,fd_max;
	socklen_t	optlen;
	struct 	sockaddr addr;

	if	(dstPort < 0 || dstPort > 65536)
	{
		printf("error port num %d\n", dstPort);
		return -1;
	}
	
	if	(srcPort < 0 || srcPort > 65536)
	{
		srcPort = 0;
	}
	
	if(timeout < 0)
	{
		timeout = 0;
	}

	tv.tv_sec	= timeout/1000;
	tv.tv_usec	= (timeout%1000)*1000;
	
	
	int fd = comm_isocket_creat(af, INTF_TCP, srcPort);
	if (fd < 0)
		return -1;
	if (af==AF_INET6)
	{
		ret = comm_make_sockAddr6((struct sockaddr_in6 *)&addr, dstHost, dstPort);
	}
	else
	{
		ret = comm_make_sockAddr((struct sockaddr_in *)&addr, dstHost, dstPort);
	}
	if(ret == 0)
	{
		close(fd);
		return -1;
	}

	ret = connect(fd, &addr, sizeof(addr));
	if (ret < 0)
	{
		if (errno == EINTR)
			goto fail;
		if (errno != EINPROGRESS && errno != EAGAIN)
		{
			ERR("connect errno=%d\n",errno);
			goto fail;
		}
		for(;;) 
		{
			fd_max = fd;
			FD_ZERO(&wfds);
			FD_SET((unsigned int)fd, &wfds);
			ret = select(fd_max + 1, NULL, &wfds, NULL, &tv);
			if (ret > 0 && FD_ISSET(fd, &wfds))
				break;
			else
				goto fail;
		}
			
		/* test error */
		optlen = sizeof(ret);
		getsockopt (fd, SOL_SOCKET, SO_ERROR, (char *)&ret, &optlen);
		if (ret != 0)
			goto fail;
		return fd;
	}
	
	return fd;
fail:
	if (fd >= 0)
        close(fd);
    return -1;
}

int comm_tcp_connect(int af, int srcPort, const char *dstHost, int dstPort)
{
	int	ret;
	struct 	sockaddr addr;

	if	(dstPort < 0 || dstPort > 65536)
	{
		printf("error port num %d\n", dstPort);
		return -1;
	}

	if	(srcPort < 0 || srcPort > 65536)
		srcPort = 0;

	int fd = comm_isocket_creat(af, INTF_TCP, srcPort);
	if (fd < 0)
		return -1;
	
	if (af == AF_INET6)
		ret = comm_make_sockAddr6((struct sockaddr_in6 *)&addr, dstHost, dstPort);
	else
		ret = comm_make_sockAddr((struct sockaddr_in *)&addr, dstHost, dstPort);
	if(ret == 0)
	{
		close(fd);
		return -1;
	}

	ret = connect(fd, &addr, sizeof(addr));
	if(ret != 0)
	{		
		close(fd);
		return -1;
	}

	return fd;
}

int comm_tcp_create(int af,const char *psz_host, int i_port)
{
	if(i_port < 0 || i_port > 65536)
	{
		printf("error port num %d\n", i_port);
		return -1;
	}
	

	int fd = comm_isocket_creat(af, INTF_TCP, i_port);
	if (fd < 0)
		return -1;

	if( listen( fd, 100 ) != 0 )
	{
		ERR("socket listen,errno=%d\n",errno);
		close( fd );
		return -1;
	}
	
	return fd;
}

int comm_tcp_listen(int af,const char *psz_host, int i_port)
{
	if(g_RtspSocket > 0)
	{
		return g_RtspSocket;
	}
	if	(i_port < 0 || i_port > 65536)
	{
		printf("error port num %d\n", i_port);
		return -1;
	}
	

	g_RtspSocket = comm_isocket_creat(af, INTF_TCP, i_port);
	if (g_RtspSocket < 0)
		return -1;

	if( listen( g_RtspSocket, 20 ) != 0 )
	{
		ERR("socket listen");
		close( g_RtspSocket );
		return -1;
	}
	
	return g_RtspSocket;
}

int comm_tcp_accept(int fd, struct sockaddr *sa)
{
	int ret;
	socklen_t salenptr;
	salenptr = sizeof(struct sockaddr);
again:
	if ( (ret = accept(fd, (struct sockaddr *)sa, &salenptr)) < 0) 
	{
		if (errno == ECONNABORTED)
			goto again;
		return -1;
	}
	
	if (sa != NULL)
		printf("recv remot peer port:%d ip:%s,\n",ntohs(((struct sockaddr_in *)sa)->sin_port), inet_ntoa(((struct sockaddr_in *)sa)->sin_addr));
	
	return ret;
}

int comm_tcp_noblock_accept(int fd, struct sockaddr *sa, int timeout)
{
	int ret = 0;
	int maxfd = fd+1;
	fd_set rfds;
	struct timeval tv;
	
	if (fd <= 0 )
		return -1;

	if(timeout < 0)
		timeout = 0;
	
	tv.tv_sec	= timeout/1000;
	tv.tv_usec	= (timeout%1000)*1000;
	
	FD_ZERO(&rfds);
	FD_SET((unsigned int)fd, &rfds);
	
	ret = select(maxfd, &rfds, NULL, NULL, &tv);
	if (ret > 0 && FD_ISSET(fd, &rfds))
	{
		return comm_tcp_accept(fd, sa);
	}
		
	return -1;
}

int comm_tcp_read(int fd, char *buf, int size, int to)
{
    int len, fd_max, ret;
    fd_set rfds;
    struct timeval tv;

	if(fd < 0)
		return -1;

	if(to < 0)
		to = 100*1000;

	tv.tv_sec = to/1000;
	tv.tv_usec = (to%1000)*1000;

    for (;;)
	{
        fd_max = fd;
        FD_ZERO(&rfds);
        FD_SET((unsigned int)fd, &rfds);

        ret = select(fd_max + 1, &rfds, NULL, NULL, &tv);
        if (ret > 0 && FD_ISSET(fd, &rfds)) 
		{
            len = recv(fd, buf, size, 0);
            if (len < 0) 
			{
                if (errno != EINTR &&errno != EAGAIN)
                    return -2;
            } 
			else 
				return len;
        } 
		else if (ret < 0) 
		{
			//SS_SYSLOG(LOG_EMERG,  (char *)"func = %s, LINE = %d, error = %d, ret = %d\n", __func__, __LINE__,errno, ret);
            return -1;
        }
		else
		{
			return 0;
		}
    }
}


int comm_tcp_exRead(int fd, char *buf, int size, int to)
{
	int size1 = 0,len = 0;
	
	while (size > 0)
	{
		len = comm_tcp_read(fd, buf + size1, size, to);
		if(len <= 0)
			break;
		size1 += len;
		size  -= len;
	}

	return size1;
}


int comm_tcp_write(int fd, char *buf, int size, int to)
{
    int ret, size1, fd_max, len;
	int selectcnt = 0;
    fd_set wfds;
    struct timeval tv;
	if(fd < 0)
		return -1;

	if(to < 0)
		to = 100*1000;

	tv.tv_sec = to/1000;
	tv.tv_usec = (to%1000)*1000;

    size1 = size;
    while (size > 0)
	{
        fd_max = fd;
        FD_ZERO(&wfds);
        FD_SET((unsigned int)fd, &wfds);
        ret = select(fd_max + 1, NULL, &wfds, NULL, &tv);
        if (ret > 0 && FD_ISSET(fd, &wfds)) 
		{
            len = send(fd, buf, size, MSG_NOSIGNAL);
            if (len < 0) 
			{
                if (errno != EINTR && errno != EAGAIN)
                {
                    return -1;
                }
                continue;
            }
            size -= len;
            buf += len;
        } 
		else if (ret < 0) 
		{
			selectcnt++;
			if(errno == EINTR||errno == EAGAIN)
			{
				if(selectcnt < 11)
				{
					usleep(50);
					continue;
				}
			}
            return -1;
        }
		else
		{
			if(errno == EINTR||errno == EAGAIN)
			{
				DBG("comm_tcp_write select timeout socket send_n eintr error\n");
			}
			else
			{
				ERR("comm_tcp_write select timeout socket error,ret=%d,errno=%d\n",ret,errno);
				return -1;
			}			
			return 0;
		}
    }

    return size1 - size;
}

int comm_tcp_write_packet(int fd, char *buf, int size, int maxMtu, int to)
{
	int	sendlen = 0;
	char *ptr = buf;

	while(size > 0)
	{
		sendlen = size > maxMtu ? maxMtu:size;
		sendlen = comm_tcp_write(fd, buf, sendlen, to);
		if(sendlen <= 0)
			break;
		buf	+= sendlen;
		size -= sendlen;
	}
	
	return buf - ptr;
}
