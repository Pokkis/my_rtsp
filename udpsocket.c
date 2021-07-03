#include "commonsocket.h"

int comm_udp_socket_read(int fd, char *buf, int size, struct sockaddr *from)
{
    int			len, ret;
    fd_set		rfds;
    struct timeval tv;
	socklen_t fromlen;

	fromlen = sizeof(struct sockaddr);
    for(;;) 
	{
        FD_ZERO(&rfds);
        FD_SET((unsigned)fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;
        ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0)
        {
            return -1;
        }
        if (!(ret > 0 && FD_ISSET(fd, &rfds)))
            continue;
        len = recvfrom(fd, buf, size, 0, from, &fromlen);
        if (len < 0) 
		{
            if (errno != EAGAIN && errno != EINTR)
                return -1;
		}
		else
		{
			break;
		}
	}

    return len;
}

int comm_udp_socket_readEx(int fd, char *buf, int size, struct sockaddr *from)
{
	int size1,len;
	
	size1 = 0;
	len   = 0;	
	while (size > 0)
	{
		len = comm_udp_socket_read(fd, buf + size1, size, from);
		if(len < 0)
			break;
		size1 += len;
		size  -= len;
	}

	return size1;
}


int comm_udp_write(int fd, char *buf, int size, struct sockaddr *to)
{
	const char *p = buf;
	unsigned short remain = size;
	int n = 0;
	short slen = 0;  

	while (remain > 0)
	{
		n = sendto (fd, p, remain, 0, to, sizeof(struct sockaddr)); 
		if (n < 0)
		{
			if (errno != EINTR && errno != EAGAIN)
			return -1;
		}

		remain -= n;
		p += n;
		slen += n;
	}

	return slen;
}

int comm_udp_write_Packet(int fd, char *buf, int size, int maxMtu, struct sockaddr *to)
{
	int		sendlen;
	char	*ptr;

	sendlen = 0;
	ptr = buf;
	while(size > 0)
	{
		sendlen = size > maxMtu ? maxMtu:size;
		sendlen = comm_udp_write(fd, buf, sendlen, to);
		if(sendlen < 0)
			break;
		buf		+= sendlen;
		size	-= sendlen;
	}
	
	return buf - ptr;
}
