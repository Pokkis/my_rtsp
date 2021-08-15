#include  <netinet/tcp.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <fcntl.h>
#include <fcntl.h>
#include "rtsphead.h"
#include "rtsptask.h"
#include "md5.h"
#include "commonsocket.h"
#include "h264read.h"

#define headerSize sizeof(fram_info_t)

RtspEnv g_Env;
Rtsp_TcpUdp_Http_Comm Com_Env;
static	int nRtspIsRunning = 0;
int	gRtspMultiFlag = 0;
int	gRtspTimeSysn = 0;
static int keepaliveflag = 0;
VIDEO_CODE_IFLAME_S gstvideocodeiflame;
static int ngRtspTimeStartFlag = 0;
static int ngRtspSetTimeFlag = 0;

int	gRtspFamily = 0;

#define MAX_MTU_COUNT 15

#define RTP_HDR_SZ 12
//#define FRAME_TYPE_I 11
struct jpeghdr {
	int 	tspec:8;
	int 	off:24;
	BYTE 	type;
	BYTE 	q;
	BYTE 	width;
	BYTE 	height;
};

struct jpeghdr_rst {
	WORD dri;
	WORD f:1;
	WORD l:1;
	WORD count:14;
};

struct jpeghdr_qtable {
	BYTE  	mbz;
	BYTE  	precision;
	WORD 	length;
};

typedef enum {
	/* start of frame */
	SOF0  = 0xc0,
	SOF1  = 0xc1,
	SOF2  = 0xc2,
	SOF3  = 0xc3,

	SOF5  = 0xc5,
	SOF6  = 0xc6,
	SOF7  = 0xc7,
	JPG   = 0xc8,
	SOF9  = 0xc9,
	SOF10 = 0xca,
	SOF11 = 0xcb,

	SOF13 = 0xcd,
	SOF14 = 0xce,
	SOF15 = 0xcf,

	DHT   = 0xc4,

	DAC   = 0xcc,

	RST0  = 0xd0,
	RST1  = 0xd1,
	RST2  = 0xd2,
	RST3  = 0xd3,
	RST4  = 0xd4,
	RST5  = 0xd5,
	RST6  = 0xd6,
	RST7  = 0xd7,

	SOI   = 0xd8,
	EOI   = 0xd9,
	SOS   = 0xda,
	DQT   = 0xdb,
	DNL   = 0xdc,
	DRI   = 0xdd,
	DHP   = 0xde,
	EXP   = 0xdf,

	APP0  = 0xe0,
	APP1  = 0xe1,
	APP2  = 0xe2,
	APP3  = 0xe3,
	APP4  = 0xe4,
	APP5  = 0xe5,
	APP6  = 0xe6,
	APP7  = 0xe7,
	APP8  = 0xe8,
	APP9  = 0xe9,
	APP10 = 0xea,
	APP11 = 0xeb,
	APP12 = 0xec,
	APP13 = 0xed,
	APP14 = 0xee,
	APP15 = 0xef,

	JPG0  = 0xf0,
	JPG1  = 0xf1,
	JPG2  = 0xf2,
	JPG3  = 0xf3,
	JPG4  = 0xf4,
	JPG5  = 0xf5,
	JPG6  = 0xf6,
	SOF48 = 0xf7,       ///< JPEG-LS
	LSE   = 0xf8,       ///< JPEG-LS extension parameters
	JPG9  = 0xf9,
	JPG10 = 0xfa,
	JPG11 = 0xfb,
	JPG12 = 0xfc,
	JPG13 = 0xfd,

	COM   = 0xfe,       /* comment */

	TEM   = 0x01,       /* temporary private use for arithmetic coding */

	/* 0x02 -> 0xbf reserved */
} JPEG_MARKER;

const BYTE map2[] =
{
	0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};
typedef struct G_RtpOverHttp_Node
{
	int		post_port;			//port method used port
	int		get_port;			//get  method used port
	int		get_fd;				//get  method used socketfd
	int		post_fd;			//port method used socketfd
	int		fmax_fd;			//the  max socketfd + 1 = fmax_fd
	int     Ex_Data_Flag;           //when post request with extra data flag set 1;
	int     IsFisrtIn;			//is   the first time request
	char	ip[32];				//ip
	char	sessionCookie[50];  //used in judge if the same connecter
	ClientSession	*clientsession;     //one session abstract struct
	struct G_RtpOverHttp_Node *prev;
	struct G_RtpOverHttp_Node *next;
	//.....other thing
}G_RtpOverHttp_St, *G_RtpOverHttp_P;

extern G_RtpOverHttp_St RtpOverHttp_Head;

#define RTP_JPEG_RESTART           0x40

static char const* allowedCommandNames = "OPTIONS, DESCRIBE, SET_PARAMETER,GET_PARAMETER, SETUP, TEARDOWN, PLAY, PAUSE";
static char const* const libNameStr = "RTSP-Server Streaming Media v2013-04-03";
const char * const libServer = "RTSP-Server/1.0.0";

static char *av_base64_encode(char * buf, int buf_len, const BYTE *src, int len);
Rtsp_av_attr *getRtspAvInfor(int nCh, int bMain);
void DestroyRtspServer(int line,RtspServer *serverHand);
int GetRtspServerState();
int SetRtspServerState(int nState);
static void incomingConnectionHandler(void * instance, int Mask);
static void  DestroyClientSession(ClientSession *clientSession);
static int DeleteAllSessionsMulti(int bMinChn);
 int DeleteAllSessions();
static int CountMultiSessionsUse(int bMinChn);
static void CheckMultiMemberKeepAlive(const int bUseMin,const struct timeval timeNow);
static int get_status_by_tcp_port(int report, int *txsize);

static char g_test_buff[512*1025];

static int Get_Video_Frame(int streamType,DWORD *timpstamp)
{
	static int iFlag = 0;
	int ret = -1;
	DWORD lastTimeStamp = 0;
	DWORD  getFrameNo  = 0;
	DWORD curTimeStamp = 0;
	RTSP_STREAM_PARAM *pStream = &g_Env.rtspSever->bVideoStream[streamType];
	if(pStream->bFirst)
	{
		pStream->lastFrameNo = 0;
	}

	fram_info_t fram_info = { 0 };
	ret = h264_read_fram(&fram_info);
	#if 1
	if(ret == 0 && iFlag == 0)
	{
		if(fram_info.fram_type != FRAME_TYPE_I)
		{		
			free(fram_info.fram_buff);
			ret = -1;
		}
		else
		{
			iFlag = 1;
		}
	}
	#endif
	//BLUE_TRACE("cdy fram_info.fram_type:%d ret:%d\n", fram_info.fram_type, ret);
	if(ret == 0)
	{
		pStream->lastFrameNo++;	
		*timpstamp = fram_info.timestamp;
		g_Env.rtspSever->bMediaType = 1;
		g_Env.rtspSever->streamType = streamType;
		g_Env.rtspSever->frametype = fram_info.fram_type;
		memcpy(g_Env.rtspSever->pTCPVideoBuf,(char*)&fram_info, headerSize);
		memcpy(g_Env.rtspSever->pTCPVideoBuf+headerSize,fram_info.fram_buff,fram_info.fram_size);
		memcpy(g_Env.rtspSever->pUDPVideoBuf,g_Env.rtspSever->pTCPVideoBuf,fram_info.fram_size+headerSize);
		memcpy(g_test_buff, g_Env.rtspSever->pTCPVideoBuf, fram_info.fram_size+headerSize);
		free(fram_info.fram_buff);
	}
	else
	{
		g_Env.rtspSever->bMediaType = -1;
	}
	//SUCCESS_TRACE("ret=%d,bFirst =%d,Get_Video_Frame *timpstamp=%d,bMediaType=%d\n",
			//ret,pStream->bFirst,*timpstamp,g_Env.rtspSever->bMediaType);
	g_Env.rtspSever->frameSize = ret;
	return ret;
}

static int Get_Audio_Frame(DWORD *timpstamp)
{
	int ret = 0;
	DWORD  getFrameNo  = 0;
	RTSP_STREAM_PARAM *pStream = &g_Env.rtspSever->bAudioStream;
	//ret = Intf_GetAudioFrame(0, g_Env.rtspSever->pTCPVideoBuf, g_Env.rtspSever->maxVideoLen,
		//pStream->lastFrameNo,&getFrameNo,&pStream->lastPos);

	if(ret > 0)
	{
		pStream->lastPos = getFrameNo+1;
		*timpstamp = 0;//((EXT_FRAME_HEAD*)(g_Env.rtspSever->pTCPVideoBuf+sizeof(ENC_FRAME_HEAD)))->nTimestamp;
		g_Env.rtspSever->bMediaType = 0;
		memcpy(g_Env.rtspSever->pUDPVideoBuf,g_Env.rtspSever->pTCPVideoBuf,ret);
	}
	else
	{
		g_Env.rtspSever->bMediaType = -1;
	}
	//BLUE_TRACE("ret=%d,Get_Audio_Frame *timpstamp=%d,bMediaType=%d\n",ret,*timpstamp,g_Env.rtspSever->bMediaType);
	g_Env.rtspSever->frameSize = ret;
	return ret;
}

int av_base64_decode(BYTE *out, const char *in, int out_length)
{
	int v = 0;
	BYTE *dst = out;

	for (int i = 0; in[i] && in[i] != '='; i++)
	{
		DWORD index= in[i]-43;
		if (index>=(sizeof(map2)/sizeof(map2[0])) || map2[index] == 0xff)
			return -1;
		v = (v << 6) + map2[index];
		if (i & 3)
		{
			if (dst - out < out_length)
			{
				*dst++ = v >> (6 - 2 * (i & 3));
			}
		}
	}

	return dst - out;
}


static char *av_base64_encode(char * buf, int buf_len, const BYTE *src, int len)
{
	static const char b64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *ret, *dst;
	DWORD i_bits = 0;
	int i_shift = 0;
	int bytes_remaining = len;

	if ((DWORD)len >= UINT_MAX / 4 || buf_len < len * 4 / 3 + 12)
		return NULL;
	ret = dst = buf;
	while (bytes_remaining) {
		i_bits = (i_bits << 8) + *src++;
		bytes_remaining--;
		i_shift += 8;

		do {
			*dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
			i_shift -= 6;
		} while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
	}
	while ((dst - ret) & 3)
		*dst++ = '=';
	*dst = '\0';

	return ret;
}

static int FindStartCode(char *buf, int len)
{
	int pos = 0;

	while(pos < len - 4)
	{
		if(buf[pos] == 0x00 && buf[pos+1] == 0x00 && buf[pos+2] == 0x00 && buf[pos+3] == 0x01)
		{
			return pos;
		}
		pos++;
	}

	return -1;
}

static int find_marker(BYTE **pbuf_ptr, BYTE *buf_end)
{
	const BYTE *buf_ptr;
	DWORD v, v2;
	int val;

	buf_ptr = *pbuf_ptr;
	while (buf_ptr < buf_end)
	{
		v = *buf_ptr++;
		v2 = *buf_ptr;
		if ((v == 0xff) && (v2 >= 0xc0) && (v2 <= 0xfe) && buf_ptr < buf_end) {
			val = *buf_ptr++;
			goto found;
		}
	}
	val = -1;
found:
	*pbuf_ptr = (BYTE *)buf_ptr;
	return val;
}

int RTSP_get_SPS_PPS(ClientSession *clientSession,char *profilelevelid, char *sps_pps, int codectype)
{
	BYTE sps[128] ={0};
	BYTE pps[128] ={0};
	char base64sps[128] ={0};
	char base64pps[128] ={0};
	int spslen = 0;
	int ppslen = 0;
	int count = 0;
	BYTE sei[128] ={0};
	BYTE vps[128] ={0};
	char base64sei[128] ={0};
	char base64vps[128] ={0};
	int seilen = 0;
	int vpslen = 0;

_restartgetspspps:

	if (clientSession->bUseMinStream == 0)
	{
		if(gstvideocodeiflame.gMainSPSlen > 4)
		{
			spslen = gstvideocodeiflame.gMainSPSlen -4;
			memcpy(sps, &gstvideocodeiflame.gMainSPSbuf[4], spslen);
		}
		if(gstvideocodeiflame.gMainPPSlen > 4)
		{
			ppslen = gstvideocodeiflame.gMainPPSlen -4;
			memcpy(pps, &gstvideocodeiflame.gMainPPSbuf[4], ppslen);
		}
		if(codectype == 5)
		{
			if(gstvideocodeiflame.gMainSEIlen > 4)
			{
				seilen = gstvideocodeiflame.gMainSEIlen -4;
				memcpy(sei, &gstvideocodeiflame.gMainSEIbuf[4], seilen);
			}
			if(gstvideocodeiflame.gMainVPSlen > 4)
			{
				vpslen = gstvideocodeiflame.gMainVPSlen -4;
				memcpy(vps, &gstvideocodeiflame.gMainVPSbuf[4], vpslen);
			}
		}

		if(spslen == 0 || ppslen == 0)
		{
			return 0;
		}
	}
	else if(clientSession->bUseMinStream == 1)
	{
		if(gstvideocodeiflame.gMinSPSlen > 4)
		{
			spslen = gstvideocodeiflame.gMinSPSlen -4;
			memcpy(sps, &gstvideocodeiflame.gMinSPSbuf[4], spslen);
		}
		if(gstvideocodeiflame.gMinPPSlen > 4)
		{
			ppslen = gstvideocodeiflame.gMinPPSlen -4;
			memcpy(pps, &gstvideocodeiflame.gMinPPSbuf[4], ppslen);
		}
		if(codectype == 5)
		{
			if(gstvideocodeiflame.gMinSEIlen > 4)
			{
				seilen = gstvideocodeiflame.gMinSEIlen -4;
				memcpy(sei, &gstvideocodeiflame.gMinSEIbuf[4], seilen);
			}
			if(gstvideocodeiflame.gMinVPSlen > 4)
			{
				vpslen = gstvideocodeiflame.gMinVPSlen -4;
				memcpy(vps, &gstvideocodeiflame.gMinVPSbuf[4], vpslen);
			}
		}
	}

	if(spslen == 0 || ppslen == 0)
	{
		if (count > 1000)
		{
			ERR("RTSP_get_SPS_PPS error\n");
			return 0;
		}

		count++;
		usleep(3000);
		goto _restartgetspspps;
	}

	sprintf(profilelevelid,"%02x%02x%02x",sps[1],sps[2],sps[3]);
	av_base64_encode(base64sps,sizeof(base64sps),(const BYTE *)sps,spslen);
	av_base64_encode(base64pps,sizeof(base64pps),(const BYTE *)pps,ppslen);
	if(codectype == 5)
	{
		av_base64_encode(base64sei,sizeof(base64sei),(const BYTE *)sei,seilen);
		av_base64_encode(base64vps,sizeof(base64vps),(const BYTE *)vps,vpslen);
		sprintf(sps_pps, "sprop-pps=%s;sprop-sps=%s;sprop-vps=%s;sprop-sei=%s;",  base64pps, base64sps, base64vps, base64sei);
	}
	else
	{
		sprintf(sps_pps, "sprop-parameter-sets=%s,%s", base64sps, base64pps);
	}

	DBG("base64sps=%s\n", base64sps);
	BYTE tmpbuf[512] ={0};
	av_base64_decode(tmpbuf, base64sps, 512);

	return 1;
}

static int our_random()
{
	return random();
}

void our_srandom(DWORD x)
{
	srandom(x);
}

long long our_random64(void)
{
	long long i;
	i = our_random();
	i <<= 32;
	i |= our_random();
	return i;
}

static struct timeval timevalDec(struct timeval time1,struct timeval time2)
{
	struct timeval ret;

	ret.tv_usec = time1.tv_usec - time2.tv_usec;


	ret.tv_sec = time1.tv_sec - time2.tv_sec;
	if(ret.tv_sec < 0 && ret.tv_usec > 0)
	{
		ret.tv_sec = ret.tv_sec + 1;
		ret.tv_usec = ret.tv_usec - 1000000;
	}

	if(ret.tv_sec > 0 && ret.tv_usec < 0)
	{
		ret.tv_sec = ret.tv_sec - 1;
		ret.tv_usec = ret.tv_usec + 1000000;
	}

	return ret;
}

void    setUrlCallback(UrlAnalysis *pf_urlAnalysis)
{
	g_Env.pf_urlAnalysis = pf_urlAnalysis;
}

int RTSP_PraseUserPwd(char *buff, char *name, char *passwd, char *uri)
{
	char *p = NULL;
	p = strstr(buff, RTSP_HDR_AUTHORIZATION);
	if (p == NULL)
	{
		return -1;
	}

	p = p+22;//p ָ��username
    while (*p == ' ') ++p;
    char parameter[512] = {0};
    char value[512] = {0};
    while (1) {
        value[0] = '\0';
        if (sscanf(p, "%[^=]=\"%[^\"]\"", parameter, value) != 2 &&
            sscanf(p, "%[^=]=\"\"", parameter) != 1) {
            break;
        }
        if (strcmp(parameter, "username") == 0) {
			memcpy(name,value,strlen(value));
        }
		/*else if (strcmp(parameter, "realm") == 0) {
            realm = strDup(value);
        }
        else if (strcmp(parameter, "nonce") == 0) {
            nonce = strDup(value);
        }*/
        else if (strcmp(parameter, "uri") == 0) {
			memcpy(uri,value,strlen(value));
        } else if (strcmp(parameter, "response") == 0) {
			memcpy(passwd,value,strlen(value));
        }

        p += strlen(parameter) + 2 /*="*/ + strlen(value) + 1 /*"*/;
        while (*p == ',' || *p == ' ') ++p;
        // skip over any separating ',' and ' ' chars
        if (*p == '\0' || *p == '\r' || *p == '\n') break;
    }
	//DBG("name=%s,uri=%s,passwd=%s\n",name,uri,passwd);

	return 0;
}

int RTSP_Prase_UriUserPwd(char const *urlSuffix,char *name, char *passwd)
{
	if(urlSuffix == NULL || strlen(urlSuffix)<=0) return -1;

	char urlSuffixBuff[256] = {0};
	memcpy(urlSuffixBuff,urlSuffix,sizeof(urlSuffixBuff));
	
	char *p = NULL;
	p = strstr(urlSuffixBuff,"&user=");
	if(p == NULL)
	{
		return -1;
	}
	
	p = p+1;
	while (*p == ' ') ++p;
	char Parameter[512] = {0};
	char Value[512] = {0};

	if(sscanf(p,"%[^=]=%[^&]&",Parameter,Value) != 2)
	{
        	return -1;
    	}
	
	if(strcmp(Parameter,"user") == 0) {
		memcpy(name,Value,strlen(Value));
    	}
	p += strlen(Parameter) +1+strlen(Value);

	while(*p == ' ') ++p;
	
	if(*p == '&')
		++p;
	else
		return -1;
	
	if(p==NULL)	return -1;
	
	memset(Parameter,0,sizeof(Parameter));
	memset(Value,0,sizeof(Value));
	if(sscanf(p, "%[^=]=%[^ ] ",Parameter,Value) != 2)
	{
        	return -1;
    	}
	
	if(strcmp(Parameter,"password") == 0) {
		memcpy(passwd,Value,strlen(Value));
    	}
	
	return 0;
}

void RTSP_GetSessionId(char *sessId, int len)
{
	for(int i=0; i<len; i++){
		sessId[i] = (char )((random()%10) + '0');
	}
	sessId[len] = 0;
}

static int TcpSetSocketNoBlock(int fd)
{
	int curFlags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, curFlags|O_NONBLOCK) >= 0;
}

static int startPipe(int fds[2])
{
	if(pipe(fds))
	{
		ERR("can't create notify pipe\n");
		return -1;
	}
	TcpSetSocketNoBlock(fds[0]);
	TcpSetSocketNoBlock(fds[1]);
	return 0;
}

RtspServer *CreatRtspServer(int rtspPort, int bUserAuth)
{
	RtspServer 	*pServerHand = (RtspServer *)malloc(sizeof(RtspServer));
	if(pServerHand == NULL)
	{
		ERR("malloc error line:%d\n", __LINE__);
		return NULL;
	}

	memset(pServerHand, 0, sizeof(RtspServer));
	if(rtspPort <= 0)
		rtspPort = 554;
	pServerHand->rtspPort = rtspPort;
	pServerHand->fIsUserAuth = bUserAuth;
	(pServerHand->fUserAuth).fIsMd5Auth = 0;
	memset(pServerHand->client, 0, sizeof(ClientSession) * MAX_CLIENT_NUM);

	if (g_Env.bPassive)
	{
		MAGENTA_TRACE("********* CreatRtspServer begin  socket=%d port=%d\n",pServerHand->rtspSocket,pServerHand->rtspPort);
		pServerHand->rtspSocket = comm_tcp_listen((gRtspFamily==0?AF_INET:AF_INET6), NULL, pServerHand->rtspPort);
		if(pServerHand->rtspSocket == -1)
		{
			//SS_SYSLOG(LOG_EMERG,  (char *)"creat rtsp socket fail PUB_SetRebootDVS LINE:%d\n",__LINE__);
			ERR("SS_PUB_SetRebootDVS\n");
			//SS_PUB_SetRebootDVS((char *)__FILE__, __LINE__);
			return NULL;
		}
		MAGENTA_TRACE("********* CreatRtspServer result  socket=%d port=%d\n",pServerHand->rtspSocket,rtspPort);
		if(pServerHand->rtspSocket < 0)
		{
			//SS_SYSLOG(LOG_ERR,  (char *)"creat rtsp socket fail\n");
			ERR("creat rtsp socket fail\n");
			DestroyRtspServer(__LINE__,pServerHand);
			return NULL;
		}

		//SS_SYSLOG(LOG_WARNING, (char *)"creat rtsp server socket %x\n",pServerHand->rtspSocket);
	}
	else
	{
		//SS_SYSLOG(LOG_DEBUG, (char *)"rtsp active open\n");
	}

	MAGENTA_TRACE("********* CreatRtspServer success  socket=%d port=%d\n",pServerHand->rtspSocket,rtspPort);
	snprintf(pServerHand->szMulticastIP, 16, "0.0.0.0");

	pServerHand->nMultiClientNum[0] = 0;
	pServerHand->nMultiClientNum[1] = 0;
	startPipe(pServerHand->fds);
	for(int i = 0; i < MAX_CLIENT_NUM; ++i)
	{
		pServerHand->pHttp_session[i] = NULL;
	}

	return pServerHand;
}

void DestroyRtspServer(int line,RtspServer *serverHand)
{
	int	i;
	ClientSession * tempClientSession;
	MAGENTA_TRACE("DestroyRtspServer begin line=%d\n",line);
	if(serverHand == NULL)
		return;
	if(serverHand->rtspSocket > 0)
	{
		serverHand->rtspSocket = 0;
	}
	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if(tempClientSession->bUse == 1)
		{
			DestroyClientSession(tempClientSession);
			BLUE_TRACE("tempClientSession->bIsActive=%d\n",tempClientSession->bIsActive);
		}
		close(serverHand->fds[0]);
		close(serverHand->fds[1]);
		serverHand->pHttp_session[i] = NULL;
	}

	if(serverHand)
	{
		free(serverHand);
		serverHand = NULL;
	}
	DBG("DestroyRtspServer end \n");
}

static void incomingConnectionHandler(void * instance, int Mask)
{
	CYAN_TRACE("incomingConnectionHandler\n");
	RtspServer *serverHand = (RtspServer *)instance;
	if(NULL == serverHand)
	{
		ERR("serverHand=%p\n",serverHand);
		return;
	}

	ClientSession * tempClientSession = NULL;
	int clientSocket;
	struct timeval timeNow;

	if (gRtspFamily)
	{
		struct sockaddr_in6 clientAddr6;
		socklen_t clientAddrLen = sizeof(clientAddr6);
		clientSocket = accept(serverHand->rtspSocket, (struct sockaddr*)&clientAddr6, &clientAddrLen);
	}
	else
	{
		struct sockaddr_in clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);
		clientSocket = accept(serverHand->rtspSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
	}
	if (clientSocket < 0)
	{
		return;
	}

	if (gRtspFamily)
		DBG("recv remot rtsp client %s\n",comm_socket_getPeerIp6(clientSocket));
	else
		DBG("recv remot rtsp client %s\n",comm_socket_getPeerIp(clientSocket));
	comm_socket_nonblock(clientSocket, 1);
	comm_setSendBufferTo(clientSocket, 512 * 1024);

	int i = 0;
	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if(tempClientSession->bUse == 0)
			break;
		continue;
	}

	if(i >= MAX_CLIENT_NUM)
	{
		ERR("more than 8 channels RTSP stream,disconnect\n");
		//SS_SYSLOG(LOG_EMERG, (char *)"more than 8 channels RTSP stream,disconnect\n");
		comm_socket_close(clientSocket);
		return;
	}

	gettimeofday(&timeNow, NULL);
	our_srandom(timeNow.tv_sec*1000 + timeNow.tv_usec/1000);
	memset(tempClientSession,0,sizeof(ClientSession));
	serverHand->clientNum++;

	//DBG("recv remot rtsp client %s, clientNum = %d\n",comm_socket_getPeerIp(clientSocket), serverHand->clientNum);
	//SS_SYSLOG(LOG_WARNING, (char *)"recv remot rtsp client %s, clientNum = %d\n",comm_socket_getPeerIp(clientSocket), serverHand->clientNum);
	tempClientSession->sock = clientSocket;
	tempClientSession->session = our_random64();
	tempClientSession->bUse = 1;
	tempClientSession->bIsActive = 1;
	tempClientSession->ourServer = serverHand;
	tempClientSession->trackId[0] = 1;
	tempClientSession->trackId[1] = 2;
	tempClientSession->HttpFlag = 0;
	tempClientSession->Http_Error_Flag = 0;
	tempClientSession->bPlaySuccess = 0;
	tempClientSession->nKeepHBCount = 0;
	memset(tempClientSession->sendBuf, 0, sizeof(tempClientSession->sendBuf));
	memset(tempClientSession->recvBuf, 0, sizeof(tempClientSession->recvBuf));
}

int SessionKeepMulti(int bMinChn,struct timeval timeNow)
{
	int				i = 0;
	ClientSession	* tempClientSession;
	RtspServer 		* serverHand = g_Env.rtspSever;

	if(serverHand == NULL)
		return 0;
	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if(tempClientSession->bSCZRequestMulticast && (tempClientSession->bUseMinStream == bMinChn) && (1 == tempClientSession->nMultiClientNo))
		{
			keepaliveflag = 1;
			tempClientSession->rtcpKeepAliveTime = timeNow;
			//DBG("!!!! SessionKeepMulti\n");
		}
	}
	return 1;
}

int DeleteAllSessionsMulti(int bMinChn)
{
	int				i = 0;
	ClientSession	* tempClientSession;
	RtspServer 		* serverHand = g_Env.rtspSever;

	if(serverHand == NULL)
		return 0;

	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if(tempClientSession->bSCZRequestMulticast && (tempClientSession->bUseMinStream == bMinChn))
		{
			tempClientSession->bIsActive = -1;
			BLUE_TRACE("tempClientSession->bIsActive=%d\n",tempClientSession->bIsActive);
		}
	}

	return 1;
}

int DeleteAllSessions()
{
	int				i = 0;
	ClientSession	* tempClientSession;
	RtspServer 		* serverHand = g_Env.rtspSever;

	if(serverHand == NULL)
		return 0;

	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		tempClientSession->bIsActive = -1;
		BLUE_TRACE("tempClientSession->bIsActive=%d\n",tempClientSession->bIsActive);
	}

	return 1;
}

int GetVideoSessionCount(int streamType,int mode)
{
	int	i = 0;
	ClientSession	*tempClientSession;
	RtspServer 		*serverHand = g_Env.rtspSever;
	int				count = 0;

	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if (tempClientSession->bUseMinStream == streamType && tempClientSession->bPlaySuccess
			&&tempClientSession->streamingMode == mode)
			count++;
	}

	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = serverHand->pHttp_session[i];
		if (tempClientSession&&tempClientSession->bUseMinStream == streamType &&
			tempClientSession->bPlaySuccess&&tempClientSession->streamingMode == mode)
			count++;
	}

	return count;
}

int GetAudioSessionCount()
{
	int	i = 0;
	ClientSession	*tempClientSession;
	RtspServer 		*serverHand = g_Env.rtspSever;
	int				count = 0;
	Rtsp_av_attr *AvAttr = NULL;
	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		AvAttr = g_Env.AvAttr + tempClientSession->nSrcChannel * 2 + tempClientSession->bUseMinStream;
		if(AvAttr->bAudioOpen&& tempClientSession->bPlaySuccess&&tempClientSession->media_stream_type != MEDIA_TYPE)
			count++;
	}
	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = serverHand->pHttp_session[i];
		if(NULL == tempClientSession)
			continue;
		AvAttr = g_Env.AvAttr + tempClientSession->nSrcChannel * 2 + tempClientSession->bUseMinStream;
		if(AvAttr->bAudioOpen&&tempClientSession->bPlaySuccess&&
			tempClientSession->media_stream_type != MEDIA_TYPE)
			count++;
	}
	return count;
}

int CountMultiSessionsUse(int bMinChn)
{
	int				i = 0;
	ClientSession	* tempClientSession;
	RtspServer 		* serverHand = g_Env.rtspSever;
	int				count = 0;

	if(serverHand == NULL)
		return 0;

	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if((tempClientSession->bUseMinStream == bMinChn) && tempClientSession->bUse && tempClientSession->bSCZRequestMulticast)
			count++;
	}

	return count;
}

ClientSession *GetMultiSessionsFirst(int bMinChn)
{
	int				i = 0;
	ClientSession	* tempClientSession;
	RtspServer 		* serverHand = g_Env.rtspSever;

	if(serverHand == NULL)
		return NULL;

	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if((tempClientSession->bUseMinStream == bMinChn) && tempClientSession->bUse && tempClientSession->bSCZRequestMulticast && tempClientSession->bForMultiKeep)
			return tempClientSession;
	}

	return NULL;
}

void DestroyClientSession(ClientSession *clientSession)
{
	int				bMinStream = 0,nCountMultiSessNum = 0;
	RtspServer		*pRtspServer = g_Env.rtspSever;

	if(pRtspServer== NULL)
		return;

	WARNING_TRACE("DestroyClientSession clientNum:%d\n",g_Env.rtspSever->clientNum);

	if(NULL == clientSession)
		return;

	clientSession->bPlaySuccess = 0;
	bMinStream = clientSession->bUseMinStream;
	nCountMultiSessNum = CountMultiSessionsUse(bMinStream);

	if(clientSession->bSCZRequestMulticast)
	{
		if(1 == clientSession->nMultiClientNo)
		{
			if(1 != nCountMultiSessNum)
			{
				clientSession->bForMultiKeep = 1;
				clientSession->bPlaySuccess = 1;
				if(clientSession->sock > 0)
				{
					comm_socket_close(clientSession->sock);
					clientSession->sock = 0;
				}
				return;
			}
		}

		if(pRtspServer->nMultiClientNum[bMinStream] > 0)
			pRtspServer->nMultiClientNum[bMinStream]--;
		else
			pRtspServer->nMultiClientNum[bMinStream] = 0;

		SUCCESS_TRACE("DestroyClientSession bSCZRequestMulticast mainMultiClientNum:%d minMultiClientNum:%d\n",
			pRtspServer->nMultiClientNum[0],pRtspServer->nMultiClientNum[1]);

	}


dellastsession:
	if(clientSession->bUse == 0)
	{
		return;
	}

	if(clientSession->sock > 0)
	{
		comm_socket_close(clientSession->sock);
	}


	if(clientSession->rtpSocket[0] > 0)
	{
		comm_socket_close(clientSession->rtpSocket[0]);
	}

	if(clientSession->rtpSocket[1] > 0)
	{
		comm_socket_close(clientSession->rtpSocket[1]);
	}

	memset(clientSession, 0, sizeof(ClientSession));
	g_Env.rtspSever->clientNum--;

	if(g_Env.rtspSever->clientNum < 0)
		g_Env.rtspSever->clientNum = 0;

	//DBG("DestroyClientSession LINE:%d client-- clientNum:%d\n",nCallLine,g_Env.rtspSever->clientNum);
	if((GetVideoSessionCount(bMinStream,RTP_TCP)+GetVideoSessionCount(bMinStream,RTP_UDP) == 0)
		&&pRtspServer->bVideoStream[bMinStream].EnableFlag==1)
	{
		pRtspServer->bVideoStream[bMinStream].EnableFlag = 0;
	}
	/*if(g_Env.rtspSever->clientNum == 0)
	{
		if(g_Env.rtspSever->pTCPVideoBuf)
			free(g_Env.rtspSever->pTCPVideoBuf);
		g_Env.rtspSever->pTCPVideoBuf = NULL;
		if(g_Env.rtspSever->pUDPVideoBuf)
			free(g_Env.rtspSever->pUDPVideoBuf);
		g_Env.rtspSever->pUDPVideoBuf = NULL;
	}*/

	nCountMultiSessNum = CountMultiSessionsUse(bMinStream);

	if(1 == nCountMultiSessNum)
	{
		clientSession = GetMultiSessionsFirst(bMinStream);
		if(clientSession)
		{
			DBG("delete last seesion multicast keep !\n");
			pRtspServer->nMultiClientNum[bMinStream] = 0;
			goto dellastsession;
		}
	}

	//SS_SYSLOG(LOG_DEBUG, (char *)"clientNum:%d\n",g_Env.rtspSever->clientNum);
}

static int parseRTSPRequestString(char const* reqStr,DWORD reqStrSize,char* resultCmdName,
	DWORD resultCmdNameMaxSize,char* resultURLPreSuffix,DWORD resultURLPreSuffixMaxSize,char* resultURLSuffix,
	DWORD resultURLSuffixMaxSize,char* resultCSeq,DWORD resultCSeqMaxSize)
{
	int parseSucceeded = 0;
	DWORD i,j,k,k1,k2,k3,n;
	char c;

	for (i = 0; i < resultCmdNameMaxSize-1 && i < reqStrSize; ++i)
	{
		char c = reqStr[i];
		if (c == ' ' || c == '\t')
		{
			parseSucceeded = 1;
			break;
		}

		resultCmdName[i] = c;
	}
	resultCmdName[i] = '\0';
	if (!parseSucceeded)
		return 0;

	j = i+1;
	while (j < reqStrSize && (reqStr[j] == ' ' || reqStr[j] == '\t'))
		++j;
	for (j = i+1; (int)j < (int)(reqStrSize-8); ++j)
	{
		if ((reqStr[j] == 'r' || reqStr[j] == 'R')
				&& (reqStr[j+1] == 't' || reqStr[j+1] == 'T')
				&& (reqStr[j+2] == 's' || reqStr[j+2] == 'S')
				&& (reqStr[j+3] == 'p' || reqStr[j+3] == 'P')
				&& reqStr[j+4] == ':' && reqStr[j+5] == '/')
		{
			j += 6;
			if (reqStr[j] == '/')
			{
				++j;
				while (j < reqStrSize && reqStr[j] != '/' && reqStr[j] != ' ')
					++j;
			} else {
				--j;
			}
			i = j;
			break;
		}
	}

	parseSucceeded = 0;
	for (k = i+1; (int)k < (int)(reqStrSize-5); ++k)
	{
		if (reqStr[k] == 'R' && reqStr[k+1] == 'T' &&
				reqStr[k+2] == 'S' && reqStr[k+3] == 'P' && reqStr[k+4] == '/')
		{
			while (--k >= i && reqStr[k] == ' ')
			{}
			k1 = k;
			while (k1 > i && reqStr[k1] != '/')
				--k1;
			if (k - k1 + 1 > resultURLSuffixMaxSize)
				return 0;
			n = 0;
			k2 = k1+1;
			while (k2 <= k)
				resultURLSuffix[n++] = reqStr[k2++];
			resultURLSuffix[n] = '\0';

			k3 = --k1;
			while (k3 > i && reqStr[k3] != '/')
				--k3;
			if (k1 - k3 + 1 > resultURLPreSuffixMaxSize)
				return 0;
			n = 0;
			k2 = k3+1;
			while (k2 <= k1)
				resultURLPreSuffix[n++] = reqStr[k2++];
			resultURLPreSuffix[n] = '\0';

			i = k + 7;
			parseSucceeded = 1;
			break;
		}
	}
	if (!parseSucceeded)
		return 0;

	parseSucceeded = 0;
	for (j = i; (int)j < (int)(reqStrSize-5); ++j)
	{
		if (reqStr[j] == 'C' && reqStr[j+1] == 'S' && reqStr[j+2] == 'e' &&
				reqStr[j+3] == 'q' && reqStr[j+4] == ':')
		{
			j += 5;
			while (j < reqStrSize && (reqStr[j] ==  ' ' || reqStr[j] == '\t')) ++j;
			for (n = 0; n < resultCSeqMaxSize-1 && j < reqStrSize; ++n,++j)
			{
				c = reqStr[j];
				if (c == '\r' || c == '\n')
				{
					parseSucceeded = 1;
					break;
				}

				resultCSeq[n] = c;
			}
			resultCSeq[n] = '\0';
			break;
		}
	}
	if (!parseSucceeded) return 0;

	return 1;
}

static char const* dateHeader()
{
	static char buf[200];
	time_t tt = time(NULL);
	strftime(buf, sizeof buf, "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&tt));

	return buf;
}

static void handleCmd_bad(ClientSession *clientSession, char const* cseq)
{
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
			"RTSP/1.0 400 Bad Request\r\n%sAllow: %s\r\n\r\n",
			dateHeader(), allowedCommandNames);
	if (clientSession->HttpFlag)
		clientSession->Http_Error_Flag = 1;
}

static void handleCmd_notSupported(ClientSession *clientSession, char const* cseq)
{
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
			"RTSP/1.0 405 Method Not Allowed\r\nCSeq: %s\r\n%sAllow: %s\r\n\r\n",
			cseq, dateHeader(), allowedCommandNames);
	if (clientSession->HttpFlag)
		clientSession->Http_Error_Flag = 1;
}

static void handleCmd_notFound(ClientSession *clientSession, char const* cseq)
{
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
			"RTSP/1.0 404 Stream Not Found\r\nCSeq: %s\r\n%s\r\n",
			cseq, dateHeader());
	if (clientSession->HttpFlag)
		clientSession->Http_Error_Flag = 1;
	else
	{
		clientSession->bIsActive = -1;
		BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
	}
}

static void handleCmd_unsupportedTransport(ClientSession *clientSession, char const* cseq)
{
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
			"RTSP/1.0 461 Unsupported Transport\r\nCSeq: %s\r\n%s\r\n",
			cseq, dateHeader());
	if (clientSession->HttpFlag)
		clientSession->Http_Error_Flag = 1;
	else
	{
		clientSession->bIsActive = -1;
		BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
	}
}


static void handleCmd_OPTIONS(ClientSession *clientSession, char const* cseq)
{
	struct timeval timeNow;

	gettimeofday(&timeNow,NULL);
	keepaliveflag = 1;
	clientSession->rtcpKeepAliveTime = timeNow;
	//DBG("!!!! handleCmd_OPTIONS\n");
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
			"RTSP/1.0 200 OK\r\nCSeq: %s\r\n%sPublic: %s\r\n\r\n",
			cseq, dateHeader(), allowedCommandNames);
}

#if HIK_VERSION
static void handleCmd_HEARTBEAT(ClientSession *clientSession, char const* cseq)
{
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),"RTSP/1.0 200 OK\r\nCSeq: %s\r\nDate: %s\r\n\r\n",
			cseq, dateHeader());
}
#endif

static int rtspURLPrefix(ClientSession *session, int clientSocket, char *urlBuffer)
{
	RtspServer *ourServer;
	struct sockaddr_in ourAddress;
	struct sockaddr_in6 ourAddress6;
	WORD portNumHostOrder;
	socklen_t namelen;
	char ip[48] = {0};

	if (clientSocket < 0)
	{
		return 0;
	}
	if (session->HttpFlag)
	{
		if (gRtspFamily)
		{
			namelen = sizeof(ourAddress6);
			getsockname(clientSocket, (struct sockaddr*)&ourAddress6, &namelen);
			sprintf(urlBuffer, "rtsp://%s:%hu/",
					inet_ntop(AF_INET6, &ourAddress6.sin6_addr, ip, INET6_ADDRSTRLEN), 80);
		}
		else
		{
		namelen = sizeof(ourAddress);
		getsockname(clientSocket, (struct sockaddr*)&ourAddress, &namelen);
		sprintf(urlBuffer, "rtsp://%s:%hu/",
				inet_ntoa(ourAddress.sin_addr), 80);
		}
		return 1;
	}
	ourServer = session->ourServer;

	if(ourServer == NULL)
	{
		return -1;
	}
	if (gRtspFamily)
	{
		namelen = sizeof(ourAddress6);
		getsockname(clientSocket, (struct sockaddr*)&ourAddress6, &namelen);
	}
	else
	{
	namelen = sizeof(ourAddress);
	getsockname(clientSocket, (struct sockaddr*)&ourAddress, &namelen);
	}

	portNumHostOrder = ourServer->rtspPort;
	if (portNumHostOrder == 554 )
	{
		if (gRtspFamily)
			sprintf(urlBuffer, "rtsp://%s/", inet_ntop(AF_INET6, &ourAddress6.sin6_addr, ip, INET6_ADDRSTRLEN));
		else
			sprintf(urlBuffer, "rtsp://%s/", inet_ntoa(ourAddress.sin_addr));
	}
	else
	{
		if (gRtspFamily)
			sprintf(urlBuffer, "rtsp://%s:%hu/",inet_ntop(AF_INET6, &ourAddress6.sin6_addr, ip, INET6_ADDRSTRLEN), portNumHostOrder);
		else
		{
			sprintf(urlBuffer, "rtsp://%s:%hu/",inet_ntoa(ourAddress.sin_addr), portNumHostOrder);
		}
	}
	return 1;
}

static void rtspURL(ClientSession *session, int clientSocket,char *urlBuffer)
{
	char urlPrefix[128] = {0};
	rtspURLPrefix(session, clientSocket, urlPrefix);
	sprintf(urlBuffer, "%s%s", urlPrefix, session->streamName);
}

static void handleCmd_DESCRIBE(ClientSession *clientSession,  char const* cseq,char const* urlSuffix)
{
	RtspServer *pRtspServer = g_Env.rtspSever;
	if(pRtspServer== NULL)
		return;
	int chn = 0,min = 0,ret;
	char spspps[512] = {0};
	char rtspurl[128]= {0};
	char sdp[1024] = {0};
	struct timeval timeNow;
	char mediasdp[1024] = {0};
	char audiosdp[256] = {0};
	char profilelevelid[32] = {0};
	
	char md5Pwd[64] = {0};
	char surveServer[64] = {0};
	char uri[128] = {0};
	char name[32] = {0};
	char pwd[64] = {0};
	//DEV_USER_S stUserCfg;
	int i = 0;

	gettimeofday(&timeNow, NULL);
	our_srandom(timeNow.tv_sec*1000 + timeNow.tv_usec/1000);

	char const* const sdpPrefixFmt =
		"v=0\r\n"
		"o=StreamingServer 3433055887 %ld%06ld IN IP4 %s\r\n"
		"s=%s\r\n"
		"e=NONE\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"%s\r\n";
	char const* const sdpPrefixFmt_Multi =
		"v=0\r\n"
		"o=StreamingServer 3433055887 %ld%06ld IN IP4 %s\r\n"
		"s=%s\r\n"
		"e=NONE\r\n"
		"c=IN IP4 %s/255\r\n"
		"t=0 0\r\n"
		"%s\r\n";

#if 1//HIK_VERSION
		char const* const   pstmediaheader = "a=Media_header:MEDIAINFO=494D4B48010100000400050000000000000000000000000000000000000000000000000000000000;";
		char const* const   pstmediaheaderplus = "a=Media_header:MEDIAINFO=494D4B48010200000400050000000000000000000000000081000000000000000000000000000000;";
		char const* const 	meidaSdpFmtVideoH265 =
		"m=video 0 RTP/AVP %d\r\n"
		"b=AS:70\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/90000\r\n"
		"a=fmtp:%d profile-level-id=%s;packetization-mode=1;%s\r\n"
		"%s"
		"a=framerate:%d\r\n"
		"%s";
		char const* const 	meidaSdpFmtVideoH264 =
		"m=video 0 RTP/AVP %d\r\n"
		"b=AS:70\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/90000\r\n"
		"a=fmtp:%d profile-level-id=%s;packetization-mode=1;%s\r\n"
		"%s"
		"a=framerate:%d\r\n"
		"a=Media_header:MEDIAINFO=494D4B48010100000400010000000000000000000000000000000000000000000000000000000000";
#else
	char const* const 	meidaSdpFmtVideoH264 =
		"m=video 0 RTP/AVP %d\r\n"
		"b=AS:70\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/90000\r\n"
		"a=fmtp:%d profile-level-id=%s;packetization-mode=1;%s\r\n"
		"%s";
#endif

	char const* const 	meidaSdpFmtVideoJpeg =
		"m=video 0 RTP/AVP %d\r\n"
		"b=AS:70\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/90000\r\n"
		"%s";

	char const* const 	meidaSdpFmtAudio =
		"m=audio 0 RTP/AVP %d\r\n"
		"b=AS:48\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/%d/1\r\n";
	char const* const 	meidaSdpFmtAudio_Multi =
		"m=audio %d RTP/AVP %d\r\n"
		"b=AS:48\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/%d/1\r\n";

	char const* const 	meidaSdpFmtAudioAAc =
		"m=audio 0 RTP/AVP %d\r\n"
		"b=AS:48\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/%d/2\r\n"
		"a=fmtp:%d streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1290\r\n";
	char const* const 	meidaSdpFmtAudioAAc_Multi =
		"m=audio %d RTP/AVP %d\r\n"
		"b=AS:48\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/%d/2\r\n"
		"a=fmtp:%d streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1290\r\n";

	char const* const 	meidaSdpFmtAudioAmr =
		"m=audio 0 RTP/AVP %d\r\n"
		"b=AS:48\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/%d/1\r\n"
		"a=fmtp:%d octet-align=1\r\n";

	char const* const 	meidaSdpFmtAudioAmr_Multi =
		"m=audio %d RTP/AVP %d\r\n"
		"b=AS:48\r\n"
		"a=control:trackID=%d\r\n"
		"a=rtpmap:%d %s/%d/1\r\n"
		"a=fmtp:%d octet-align=1\r\n";
	char ipAddressStr[32] = {0};
	char sourceFilterLine[128] = {0};

	Rtsp_av_attr *AvAttr = NULL;
	if (gRtspFamily)
		sprintf(ipAddressStr, (char *)comm_socket_getIp6(clientSession->sock));
	else
		sprintf(ipAddressStr, (char *)comm_socket_getIp(clientSession->sock));

	clientSession->bIsMulticast = gRtspMultiFlag;

	if (clientSession->bIsMulticast)
	{
		const char* const sourceFilterFmt = "a=source-filter: incl IN IP4 * %s\r\na=rtcp-unicast: reflection\r\n";
		sprintf(sourceFilterLine, sourceFilterFmt,ipAddressStr);
	}

	rtspURL(clientSession,clientSession->sock, rtspurl);
	if(clientSession->ourServer&&clientSession->ourServer->fIsUserAuth)
	{
		if(strstr((char *)clientSession->recvBuf,RTSP_HDR_AUTHORIZATION)!=NULL)
		{
			ret = RTSP_PraseUserPwd((char *)clientSession->recvBuf, name, pwd, uri);
			if(ret == -1)
			{
				RTSP_GetSessionId(clientSession->nonce, 8);
				snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
							"RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\n"
							"Server: %s\r\n"
				 			"WWW-Authenticate: Digest "
							"realm=\"Surveillance Server\", nonce=\"%s\"\r\n\r\n",
							cseq,libServer,clientSession->nonce);
				return;
			}
			for(i=0; i<3; i++)
			{
				//SS_PARAM_GET_USER_CONFIG(i, &stUserCfg);
				ret = strcmp("admin", name);
				if(ret != 0)	
				{
					continue;
				}
				
				memset(md5Pwd, 0, 64);
				memset(surveServer, 0, 64);
				strncpy(surveServer, "Surveillance Server", 20);
				
				MD5Auth_BuildAuthResonseWithMD5((char *)md5Pwd, 64,0, name, surveServer, "admin", 
												clientSession->nonce,NULL, NULL, NULL, "DESCRIBE", uri);
				
				ret = strcmp(md5Pwd, pwd);
				if(ret != 0)	
				{
					continue;			
				}

				break;
			}
		}
		else
		{
			ret = RTSP_Prase_UriUserPwd(urlSuffix,name,pwd);
			if(ret == -1)
			{
				RTSP_GetSessionId(clientSession->nonce, 8);
				snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
							"RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\n"
							"Server: %s\r\n"
				 			"WWW-Authenticate: Digest "
							"realm=\"Surveillance Server\", nonce=\"%s\"\r\n\r\n",
							cseq,libServer,clientSession->nonce);
				return;
			}
			for(i=0; i<3; i++)
			{
				ret = strcmp("admin", name);
				if(ret != 0)	
				{
					continue;
				}
				ret = strcmp("admin", pwd);
				if(ret != 0)	
				{
					continue;			
				}
				break;
			}
		}
		
		if(i >= 3)
		{
			RTSP_GetSessionId(clientSession->nonce, 8);
			snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
						"RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\n"
						"Server: %s\r\n"
						"WWW-Authenticate: Digest "
						"realm=\"Surveillance Server\", nonce=\"%s\"\r\n\r\n",
						cseq,libServer,clientSession->nonce);
			return;
		}
	}

	if(strlen(urlSuffix) > 0)
	{
		if(g_Env.pf_urlAnalysis)
		{
#if HIK_VERSION
			if (strcmp(urlSuffix, "av_stream")==0)
			{
				g_Env.pf_urlAnalysis((char *)clientSession->recvBuf,&chn, &min);
			}
			else
			{
				g_Env.pf_urlAnalysis((char *)urlSuffix, &chn, &min);
			}
#else
			g_Env.pf_urlAnalysis((char *)urlSuffix, &chn, &min);
#endif
			CYAN_TRACE("chn=%d,min=%d\n",chn,min);
		}
		else
		{
			if(sscanf(urlSuffix,"av%d_%d", &chn, &min) == 2)
			{
#if IPC_THIRD_STREAM
				if(chn > g_Env.maxChn -1 || chn < 0 || min > 3 || min < 0)
				{
					handleCmd_notFound(clientSession, cseq);
					return;
				}
#else
				if(chn > g_Env.maxChn -1 || chn < 0 || min > 2 || min < 0)
				{
					handleCmd_notFound(clientSession, cseq);
					return;
				}
#endif

			}
		}
	}
	clientSession->nSrcChannel = chn;
	clientSession->bUseMinStream = min;		
	AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;
	sprintf(AvAttr->videoCodec,"H264");
	AvAttr->videoPt = 96;

	if(strcmp(AvAttr->videoCodec,"H264") == 0)
	{
		RTSP_get_SPS_PPS(clientSession,profilelevelid, spspps, 4);   //ljh20130403
	}
	else if(strcmp(AvAttr->videoCodec,"H265") == 0)
	{
		RTSP_get_SPS_PPS(clientSession,profilelevelid, spspps, 5);   //ljh20130403
	}

#if FUHONG_VERSION
	if(AvAttr->bAudioOpen && 0)
#else
	if(AvAttr->bAudioOpen)
#endif
	{
		if(strcmp(AvAttr->audioCodec ,"MPEG4-GENERIC") == 0)
		{
			if(pRtspServer->bMulticast)
			{
				snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudioAAc_Multi,pRtspServer->nAudioPort[clientSession->bUseMinStream],AvAttr->audioPt,
					clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate,AvAttr->audioPt);
			}
			else
			{
				snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudioAAc,AvAttr->audioPt,
					clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate,AvAttr->audioPt);
			}
		}
		else if(strcmp(AvAttr->audioCodec ,"AMR") == 0)
		{
			if(pRtspServer->bMulticast)
			{
				snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudioAmr_Multi,pRtspServer->nAudioPort[clientSession->bUseMinStream],AvAttr->audioPt,
					clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate,AvAttr->audioPt);
			}
			else
			{
				snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudioAmr,AvAttr->audioPt,
					clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate,AvAttr->audioPt);
			}
		}
		else
		{
			if (!clientSession->HttpFlag)  //when get stream through http can't support audio ????
			{
				if(pRtspServer->bMulticast)
				{
					snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudio_Multi,0,AvAttr->audioPt,
					    clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate);
				}
				else
				{
					snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudio,AvAttr->audioPt,
						clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate);
				}
			}
			else
			{
				snprintf(audiosdp, sizeof(audiosdp),meidaSdpFmtAudio,AvAttr->audioPt,
						clientSession->trackId[1],AvAttr->audioPt,AvAttr->audioCodec,AvAttr->audioSampleRate);
			}
		}
	}
	if(strcmp(AvAttr->videoCodec,"H264")==0)
	{

		snprintf(mediasdp, sizeof(mediasdp),meidaSdpFmtVideoH264,AvAttr->videoPt,
			clientSession->trackId[0],AvAttr->videoPt,AvAttr->videoCodec,AvAttr->videoPt, profilelevelid, spspps,audiosdp, 25);

		//DBG("h264 nCHn = %d  sdp %s\n", chn, mediasdp);
	}
	else if(strcmp(AvAttr->videoCodec,"JPEG")==0)
	{
		snprintf(mediasdp, sizeof(mediasdp),meidaSdpFmtVideoJpeg,AvAttr->videoPt,
				clientSession->trackId[0],AvAttr->videoPt,AvAttr->videoCodec,audiosdp);
	}
	else if(strcmp(AvAttr->videoCodec,"H265")==0)
	{
		snprintf(mediasdp, sizeof(mediasdp),meidaSdpFmtVideoH265,AvAttr->videoPt,
			clientSession->trackId[0],AvAttr->videoPt,AvAttr->videoCodec,AvAttr->videoPt, profilelevelid, spspps,audiosdp, 25, pstmediaheader);

		//DBG("h264 nCHn = %d  sdp %s\n", chn, mediasdp);
	}

	if(pRtspServer->bMulticast || clientSession->bIsMulticast)
	{
		snprintf(sdp, sizeof(sdp),
			sdpPrefixFmt_Multi,timeNow.tv_sec,timeNow.tv_usec,
			ipAddressStr,clientSession->streamName,
			pRtspServer->szMulticastIP,mediasdp);
	}
	else
	{
		snprintf(sdp, sizeof(sdp),
			sdpPrefixFmt,timeNow.tv_sec,timeNow.tv_usec,
			ipAddressStr,clientSession->streamName,
			mediasdp);
	}
	snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
			"RTSP/1.0 200 OK\r\nCSeq: %s\r\n"
			"Server: %s\r\n"
			"%s"
			"Content-Type: application/sdp\r\n"
			"Content-Base: %s\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",
			cseq,
			libServer,
			dateHeader(),
			rtspurl,
			strlen(sdp),
			sdp);
	//SS_VENC_RequestIFrame(clientSession->nSrcChannel, clientSession->bUseMinStream, 1);
	clientSession->bIsMulticast = 0;
}


static void parseTransportHeader(char const* buf,int *streamingMode,char* streamingModeString,
		char* destinationAddressStr,BYTE *destinationTTL,WORD *clientRTPPortNum,
		WORD *clientRTCPPortNum,BYTE *rtpChannelId,BYTE *rtcpChannelId,DWORD  *bMulticast)
{
	WORD p1, p2;
	DWORD ttl, rtpCid, rtcpCid;
	char const* fields;
	char *pstarttmp = NULL;
	char *pendtmp = NULL;
	char field[512] = {0};
	char tmpbuf[64] = {0};

	*streamingMode = RTP_UDP;
	*destinationTTL = 255;
	*clientRTPPortNum = 0;
	*clientRTCPPortNum = 1;
	*rtpChannelId = *rtcpChannelId = 0xFF;

	*bMulticast = 0;

#if HIK_VERSION
	while (1)
	{
		if (*buf == '\0')
		{
			return;
		}
		if (strncasecmp(buf, "Transport:", 10) == 0)
			break;
		++buf;
	}

	fields = buf + 10;

	if (fields[0] == 32)
	{
		fields = buf+11;
	}
#else
	while (1) {
		if (*buf == '\0')
			return;
		if (strncasecmp(buf, "Transport: ", 11) == 0)
			break;
		++buf;
	}


	fields = buf + 11;
#endif

	if(strstr(buf,"multicast"))
	{
		*bMulticast = 1;
	}

	while (sscanf(fields, "%[^;]", field) == 1)
	{
		if (strcmp(field, "RTP/AVP/TCP") == 0)
		{
			*streamingMode = RTP_TCP;
		}
		else if (strcmp(field, "RAW/RAW/UDP") == 0 ||strcmp(field, "MP2T/H2221/UDP") == 0)
		{
			*streamingMode = RAW_UDP;
			sprintf(streamingModeString,field);
		}
		else if (strstr(field, "destination=") != NULL)
		{
			pstarttmp = strstr((char *)buf, "destination=");
			if(pstarttmp != NULL)
			{
				pendtmp = strstr(pstarttmp, ";");
				if(pstarttmp != NULL)
				{
					memcpy(tmpbuf, pstarttmp + 12, pendtmp - pstarttmp - 12);
					memcpy(destinationAddressStr, tmpbuf, strlen(tmpbuf));
				}
		}
		}
		else if (sscanf(field, "ttl%u", &ttl) == 1)
		{
			*destinationTTL = (BYTE)ttl;
		}
		else if (sscanf(field, "client_port=%hu-%hu", &p1, &p2) == 2)
		{
			*clientRTPPortNum = p1;
			*clientRTCPPortNum = p2;
		}
		else if (sscanf(field, "port=%hu-%hu", &p1, &p2) == 2)
		{
			*clientRTPPortNum = p1;
			*clientRTCPPortNum = p2;
		}
		else if (sscanf(field, "client_port=%hu", &p1) == 1)
		{
			*clientRTPPortNum = p1;
			*clientRTCPPortNum = *streamingMode == RAW_UDP ? 0 : p1 + 1;
		}
		else if (sscanf(field, "interleaved=%u-%u", &rtpCid, &rtcpCid) == 2)
		{
			*rtpChannelId = (BYTE)rtpCid;
			*rtcpChannelId = (BYTE)rtcpCid;
		}

		fields += strlen(field);
		while (*fields == ';')
			++fields;
		if (*fields == '\0' || *fields == '\r' || *fields == '\n')
			break;
	}
}


static void handleCmd_SETUP(ClientSession *clientSession,  char const* cseq,char const* urlPreSuffix, char const* urlSuffix)
{
	static WORD lastRtpPort = 8000;
	int streamingMode;
	char streamingModeString[64]   = {0};
	char destinationAddressStr[64] = {0};
	BYTE destinationTTL;
	WORD clientRTPPortNum;
	WORD clientRTCPPortNum;
	BYTE rtpChannelId;
	BYTE rtcpChannelId;
	char soureIp[32] = {0};
	WORD serverRtpPort = 0;
	WORD serverRtcpPort = 0;
	RtspServer		*pRtspServer = g_Env.rtspSever;
	DWORD  bRequestMulticast = 0;
	WORD	mPort = 0;
#if FUHONG_VERSION
	NETAPP_UPNP_S    stUpnpConfig;
#endif
	if(pRtspServer== NULL)
		return;

	if ((strstr(clientSession->recvBuf, "trackID=1")|| strstr(clientSession->recvBuf, "track1"))&& clientSession->media_stream_type == 0)
	{
		mPort = pRtspServer->nVideoPort[clientSession->bUseMinStream];
		clientSession->media_stream_type = MEDIA_TYPE;
	}
	else if ((strstr(clientSession->recvBuf, "trackID=2")|| strstr(clientSession->recvBuf, "track2"))&& clientSession->media_stream_type == 0)
	{
		mPort = pRtspServer->nAudioPort[clientSession->bUseMinStream];
		clientSession->media_stream_type = AUDIO_TYPE;
		if(clientSession->mediaNum == 0)
			clientSession->mediaNum++;
	}
	else
	{
		clientSession->media_stream_type = MIXED_TYPE;
		if (strstr(clientSession->recvBuf, "trackID=2") != NULL)
		{
			mPort = pRtspServer->nAudioPort[clientSession->bUseMinStream];
		}
	}

	parseTransportHeader(clientSession->recvBuf, &streamingMode,streamingModeString,destinationAddressStr,
			&destinationTTL, &clientRTPPortNum, &clientRTCPPortNum, &rtpChannelId, &rtcpChannelId,&bRequestMulticast);

	clientSession->streamingMode = streamingMode;
	sprintf(clientSession->destinationAddressStr, destinationAddressStr);
	clientSession->clientRTPPortNum[clientSession->mediaNum] = clientRTPPortNum;
	clientSession->clientRTCPPortNum[clientSession->mediaNum] = clientRTCPPortNum;
	clientSession->rtpChannelId[clientSession->mediaNum] = rtpChannelId;
	clientSession->trackId[clientSession->mediaNum] = clientSession->mediaNum;
	clientSession->ssrc[clientSession->mediaNum] = (DWORD)our_random();

	clientSession->bForMultiKeep = 0;

	if(bRequestMulticast)
	{
		strcpy(clientSession->destinationAddressStr,pRtspServer->szMulticastIP);
		clientSession->clientRTPPortNum[clientSession->mediaNum] = mPort;
		clientSession->clientRTCPPortNum[clientSession->mediaNum] = mPort+1;
		clientSession->bSCZRequestMulticast = 1;
	}
	else
		clientSession->bSCZRequestMulticast = 0;

	clientSession->nMultiClientNo = 0;

	if(clientSession->streamingMode != RTP_TCP)
	{
		if(clientSession->mediaNum == 0)
		{
			clientSession->rtpSocket[clientSession->mediaNum] = comm_isocket_creat((gRtspFamily==0?AF_INET:AF_INET6),INTF_UDP,lastRtpPort);
			if (gRtspFamily)
				serverRtpPort = comm_socket_getPort6(clientSession->rtpSocket[clientSession->mediaNum]);
			else
				serverRtpPort = comm_socket_getPort(clientSession->rtpSocket[clientSession->mediaNum]);
		}
		else
		{
			serverRtpPort = 2 + clientSession->serverRTPPortNum[clientSession->mediaNum - 1];
			clientSession->rtpSocket[clientSession->mediaNum] =
				comm_isocket_creat((gRtspFamily==0?AF_INET:AF_INET6), INTF_UDP,serverRtpPort);
		}

		if((serverRtpPort & 1) != 0)
		{
			comm_socket_close(clientSession->rtpSocket[clientSession->mediaNum]);
			serverRtpPort += 1;
			clientSession->rtpSocket[clientSession->mediaNum] =
				comm_isocket_creat((gRtspFamily==0?AF_INET:AF_INET6), INTF_UDP,serverRtpPort);
		}

		lastRtpPort += 2;
		if(lastRtpPort < 8000 )
			lastRtpPort = 8000;
		serverRtcpPort = serverRtpPort + 1;
		clientSession->serverRTPPortNum[clientSession->mediaNum] = serverRtpPort;

	}

	if (gRtspFamily)
		sprintf(soureIp,(char *)comm_socket_getIp6(clientSession->sock));
	else
		sprintf(soureIp,(char *)comm_socket_getIp(clientSession->sock));

	if(strlen(clientSession->destinationAddressStr) == 0)
	{
		if (gRtspFamily)
			sprintf(clientSession->destinationAddressStr, comm_socket_getPeerIp6(clientSession->sock));
		else
		{
			// barney 2016.10.13
			char *p = comm_socket_getPeerIp(clientSession->sock);
			if( p != NULL )
				strcpy(clientSession->destinationAddressStr, p);
		}
	}

	if(clientSession->bIsMulticast)
	{
		switch (streamingMode)
		{
			case RTP_UDP:
				snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
						"RTSP/1.0 200 OK\r\n"
						"CSeq: %s\r\n"
						"%s"
						"Transport: RTP/AVP;multicast;destination=%s;source=%s;port=%d-%d;ttl=%d\r\n"
						"Session: %lld\r\n\r\n",
						cseq,
						dateHeader(),
						clientSession->destinationAddressStr, soureIp,
						serverRtpPort,serverRtcpPort, destinationTTL,
						clientSession->session);
				break;
			case RTP_TCP:
				// multicast streams can't be sent via TCP
				handleCmd_unsupportedTransport(clientSession, cseq);
				break;
			case RAW_UDP:
				snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
						"RTSP/1.0 200 OK\r\n"
						"CSeq: %s\r\n"
						"%s"
						"Transport: %s;multicast;destination=%s;source=%s;port=%d;ttl=%d\r\n"
						"Session: %lld\r\n\r\n",
						cseq,
						dateHeader(),
						streamingModeString, clientSession->destinationAddressStr, soureIp,serverRtpPort, destinationTTL,
						clientSession->session);
				break;
		}
	}
	else
	{
		if(bRequestMulticast)
		{
			switch (streamingMode)
			{
			case RTP_UDP:
				snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
					"RTSP/1.0 200 OK\r\n"
					"CSeq: %s\r\n"
					"%s"
					"Transport: RTP/AVP;multicast;destination=%s;source=%s;port=%d-%d;ttl=%d\r\n"
					"Session: %lld\r\n\r\n",
					cseq,
					dateHeader(),
					pRtspServer->szMulticastIP, soureIp,
					clientSession->clientRTPPortNum[clientSession->mediaNum],clientSession->clientRTCPPortNum[clientSession->mediaNum], destinationTTL,
					clientSession->session);
				break;
			case RTP_TCP:
				handleCmd_unsupportedTransport(clientSession, cseq);
				break;
			case RAW_UDP:
				snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
					"RTSP/1.0 200 OK\r\n"
					"CSeq: %s\r\n"
					"%s"
					"Transport: %s;multicast;destination=%s;source=%s;port=%d;ttl=%d\r\n"
					"Session: %lld\r\n\r\n",
					cseq,
					dateHeader(),
					streamingModeString, pRtspServer->szMulticastIP, soureIp,serverRtpPort, destinationTTL,
					clientSession->session);
				break;
			}

		}
		else
		{
			switch (streamingMode)
			{
				case RTP_UDP:
					{
						snprintf(clientSession->sendBuf, sizeof(clientSession->sendBuf),
								"RTSP/1.0 200 OK\r\n"
								"CSeq: %s\r\n"
								"Server: %s\r\n"
								"%s"
								"Session: %lld\r\n"
								"Transport: RTP/AVP;unicast;client_port=%d-%d;source=%s;server_port=%d-%d;ssrc=%08x\r\n\r\n",
								cseq,
								libServer,
								dateHeader(),
								clientSession->session,
								clientSession->clientRTPPortNum[clientSession->mediaNum],
								clientSession->clientRTCPPortNum[clientSession->mediaNum],soureIp, serverRtpPort,serverRtcpPort,
								clientSession->ssrc[clientSession->mediaNum]);
							#if FUHONG_VERSION
								{

									DBG("rtsp str %s \n",clientSession->sendBuf);
									//��̬Ӱ��˿�?
									BLUE_TRACE("rtsp ----serverRtcpPort = %d,serverRtpPort = %d\n",serverRtcpPort,serverRtpPort);

									SS_PARAM_GET_NETAPP_UPNP_CONFIG(&stUpnpConfig);
									stUpnpConfig.wNowServerRtcpPort = serverRtcpPort;
									stUpnpConfig.wNowServerRtpPort = serverRtpPort;
									//stUpnpConfig.wSetServerRtcpPort = serverRtcpPort;
									//stUpnpConfig.wSetServerRtpPort = serverRtpPort;
									SS_PARAM_SET_NETAPP_UPNP_CONFIG(&stUpnpConfig, NULL);
									SS_UPNP_SetRefresh(2);

									DBG("rtsp --------serverRtcpPort = %d   ,   serverRtpPort = %d \n",serverRtcpPort,serverRtpPort);

								}
							#endif
						break;
					}
				case RTP_TCP:
					{
						snprintf(clientSession->sendBuf, sizeof (clientSession->sendBuf),
								"RTSP/1.0 200 OK\r\n"
								"CSeq: %s\r\n"
								"Server: %s\r\n"
								"%s"
								"Session: %lld\r\n"
								"Transport: RTP/AVP/TCP;unicast;source=%s;interleaved=%d-%d;ssrc=%08x\r\n\r\n",
								cseq,
								libServer,
								dateHeader(),
								clientSession->session, soureIp, rtpChannelId, rtcpChannelId,
								clientSession->ssrc[clientSession->mediaNum]);
						break;
					}
				case RAW_UDP:
					{
						snprintf(clientSession->sendBuf, sizeof (clientSession->sendBuf),
								"RTSP/1.0 200 OK\r\n"
								"CSeq: %s\r\n"
								"%s"
								"Transport: %s;unicast;destination=%s;source=%s;client_port=%d;server_port=%d\r\n"
								"Session: %lld\r\n\r\n",
								cseq,
								dateHeader(),
								streamingModeString, clientSession->destinationAddressStr, soureIp, clientSession->clientRTPPortNum[clientSession->mediaNum],
								serverRtpPort,clientSession->session);
						break;
					}
			}
		}
	}
	if(clientSession->mediaNum == 0)
		clientSession->mediaNum += 1;
}

static void handleCmd_TEARDOWN(ClientSession *subsession, char const* cseq)
{
	snprintf(subsession->sendBuf, sizeof(subsession->sendBuf),
			"RTSP/1.0 200 OK\r\nCSeq: %s\r\n%s\r\n",
			cseq, dateHeader());
	if (subsession->HttpFlag)
		subsession->Http_Error_Flag = 1;
	else
	{
		subsession->bIsActive = -1;
		BLUE_TRACE("subsession->bIsActive=%d\n",subsession->bIsActive);
	}
}

static void handleCmd_PAUSE(ClientSession* subsession, char const* cseq)
{
	snprintf(subsession->sendBuf, sizeof(subsession->sendBuf),
			"RTSP/1.0 200 OK\r\nCSeq: %s\r\n%sSession: %lld\r\n\r\n",
			cseq, dateHeader(), subsession->session);
	subsession->bPlaySuccess = 0;
	BLUE_TRACE("subsession->bPlaySuccess=%d\n",subsession->bPlaySuccess);
}

static void handleCmd_GET_PARAMETER(ClientSession* subsession, char const* cseq)
{
	struct timeval timeNow;
	gettimeofday(&timeNow,NULL);
	keepaliveflag = 1;
	subsession->rtcpKeepAliveTime = timeNow;
	//DBG("!!!! handleCmd_GET_PARAMETER\n");
	snprintf(subsession->sendBuf, sizeof(subsession->sendBuf),
			"RTSP/1.0 200 OK\r\nCSeq: %s\r\n%sSession: %lld\r\n\r\n",
			cseq, dateHeader(), subsession->session);
	if(subsession->bSCZRequestMulticast)
		SessionKeepMulti(subsession->bUseMinStream,timeNow);

}

static void handleCmd_SET_PARAMETER(ClientSession* subsession, char const* cseq)
{
	struct timeval timeNow;
	gettimeofday(&timeNow,NULL);
	keepaliveflag = 1;
	subsession->rtcpKeepAliveTime = timeNow;
	//DBG("!!!! handleCmd_SET_PARAMETER\n");
	snprintf(subsession->sendBuf, sizeof(subsession->sendBuf),
			"RTSP/1.0 200 OK\r\nCSeq: %s\r\n%sSession: %lld\r\n\r\n",
			cseq, dateHeader(), subsession->session);
}

static void handleCmd_PLAY(ClientSession* clientSession,char const*  cseq, char *urlPreSuffix, char *urlSuffix)
{
	RtspServer *serverHand = g_Env.rtspSever;
	if(serverHand == NULL)
		return;
	char playinfo[256] = {0};
	char rtspurl[128] = {0};
	int	trackId = 1;
	struct timeval timeNow;
	int	wificonnection = 0;
	
	int limt_size = 1024*1024;
	if( clientSession->bUseMinStream == 1 || clientSession->bUseMinStream == 2)
	{
		limt_size = 128 * 1024;
	}

	Rtsp_av_attr *AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;
	if(AvAttr == NULL)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"avattr error line:%d\n",__LINE__);
		return;
	}
	char const* const playFmt1 = "RTP-Info: url=%s/trackID=%d";
	if(strlen(urlPreSuffix) != 0&&sscanf(urlPreSuffix,"trackID=%d", &trackId) != 1)
	{
		trackId = 1;
	}
	rtspURL(clientSession,clientSession->sock, rtspurl);
	gettimeofday(&timeNow, NULL);
	our_srandom(timeNow.tv_sec*1000 + timeNow.tv_usec/1000);
	clientSession->seq[0] = (WORD)our_random();
	clientSession->rtptime[0] = (DWORD) our_random();
	clientSession->seq[1] = (WORD)our_random();
	clientSession->rtptime[1] = (DWORD) our_random();
	snprintf(playinfo, sizeof(playinfo), playFmt1, rtspurl, trackId);

	if(AvAttr->bAudioOpen)
		sprintf(playinfo, "%s,url=%s/trackID=%d\r\n\r\n",playinfo,rtspurl,trackId+1);
	else
		sprintf(playinfo, "%s\r\n\r\n",playinfo);

	snprintf((char*)clientSession->sendBuf, sizeof (clientSession->sendBuf),
			"RTSP/1.0 200 OK\r\n"
			"CSeq: %s\r\n"
			"Server: %s\r\n"
			"%s"
			"Session: %lld\r\n"
			"%s",
			cseq,libServer,dateHeader(),clientSession->session,playinfo);


	if (!clientSession->HttpFlag)
	{
		if(clientSession->bSCZRequestMulticast)
		{
			if(clientSession->bPlaySuccess!=1)
				g_Env.rtspSever->nMultiClientNum[clientSession->bUseMinStream]++;
			g_Env.rtspSever->nMultiClientNum[clientSession->bUseMinStream] = CountMultiSessionsUse(clientSession->bUseMinStream);
			clientSession->nMultiClientNo = g_Env.rtspSever->nMultiClientNum[clientSession->bUseMinStream];
		}

		if(clientSession->bSCZRequestMulticast && (clientSession->nMultiClientNo>1)&&
			g_Env.rtspSever->nMultiClientNum[clientSession->bUseMinStream]>1)
		{
			SUCCESS_TRACE(" !!!!!  for multicast users is over two,ignore send nMultiClientNo=%d bMin:%d MultiNum:%d\n",
				clientSession->nMultiClientNo,clientSession->bUseMinStream,g_Env.rtspSever->nMultiClientNum[clientSession->bUseMinStream]);

		}
		else
		{
			if(clientSession->streamingMode == RTP_TCP)
			{
				if (setsockopt(clientSession->sock, SOL_SOCKET, SO_SNDBUF, (void *)&limt_size, sizeof(limt_size)) < 0)
				{
					ERR("setsockopt:SO_SNDBUF Error\n");
				}

				clientSession->bwifiFlag = wificonnection;
			}
			else
			{
				if(clientSession->bSCZRequestMulticast)
				{
					int  ttl = 255,nLoop=0;
					if(setsockopt(clientSession->rtpSocket[0],IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl))<0)
					{
						ERR("set ttl failed!\n");
					}
					if(setsockopt(clientSession->rtpSocket[0],IPPROTO_IP, IP_MULTICAST_LOOP,&nLoop,sizeof(nLoop))<0)
					{
						ERR("set multicast loop failed!\n");
					}
				}

				if( setsockopt( clientSession->rtpSocket[0], SOL_SOCKET, SO_SNDBUF, (void *)&limt_size, sizeof(limt_size)) < 0)
				{
					ERR("set SO_SNDBUF failed!\n");
				}

			}
		}
	}
	keepaliveflag = 0;
	clientSession->rtcpKeepAliveTime = timeNow;
	clientSession->bPlaySuccess = 1;
	if(g_Env.rtspSever->bVideoStream[clientSession->bUseMinStream].EnableFlag==0)
	{
		g_Env.rtspSever->bVideoStream[clientSession->bUseMinStream].EnableFlag = 1;
	}
}

static void handleCmd_withinSession(ClientSession *clientSession,char *cmdName, char *urlPreSuffix, char *urlSuffix, char *cseq)
{
	if (strcmp(cmdName, "TEARDOWN") == 0) {
		handleCmd_TEARDOWN(clientSession, cseq);
	}
	else if (strcmp(cmdName, "PLAY") == 0) {
		handleCmd_PLAY(clientSession, cseq,urlPreSuffix,urlSuffix);
	}
	else if (strcmp(cmdName, "PAUSE") == 0) {
		handleCmd_PAUSE(clientSession, cseq);
	}
	else if (strcmp(cmdName, "GET_PARAMETER") == 0) {
		if(clientSession->bPlaySuccess == 1)
			handleCmd_GET_PARAMETER(clientSession, cseq);
		else
			handleCmd_TEARDOWN(clientSession, cseq);
	}
	else if(strcmp(cmdName, "SET_PARAMETER") == 0) {
		handleCmd_SET_PARAMETER(clientSession, cseq);
	}
}

void incomingConnectionHandlerClient(void * instance, int Mask)
{
	ClientSession *clientSession = (ClientSession *)instance;
	int  bytesRead,endOfMsg;
	char *ptr = clientSession->recvBuf;
	char cmdName[128] = {0};
	char urlPreSuffix[128] = {0};
	char urlSuffix[128] = {0};
	char cseq[32] = {0};
	struct timeval timeNow;
	int  ret = 0;
	if(Mask > 0)
	{
		recv(clientSession->rtpSocket[Mask - 1], ptr, 4096, 0);
		return;
	}
	if (!clientSession->HttpFlag)
	{
		memset(ptr, 0, sizeof(clientSession->recvBuf));
		memset(clientSession->sendBuf, 0, sizeof(clientSession->sendBuf));
		bytesRead = recv(clientSession->sock, ptr, 4096, 0);
		if(bytesRead <= 0)
		{
			if(bytesRead == -1 &&errno != EINTR && errno != EAGAIN)
			{
				clientSession->bIsActive = -1;
				BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
			}
			else if(bytesRead == 0)
			{
				clientSession->bIsActive = -1;
				BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
			}
			return;
		}

		clientSession->recvBuf[bytesRead] = '\0';
	}
	else
	{
		memset(clientSession->sendBuf, 0, sizeof(clientSession->sendBuf));
		bytesRead = strlen(clientSession->recvBuf)+1;
	}

	gettimeofday(&timeNow,NULL);
	clientSession->rtcpKeepAliveTime = timeNow;
	keepaliveflag = 1;

	char *tmpPtr = ptr;
	char *fLastCRLF = ptr - 3;
	--tmpPtr;
	while (tmpPtr < &ptr[bytesRead-1])
	{
		if (*tmpPtr == '\r' && *(tmpPtr+1) == '\n')
		{
			if (tmpPtr - fLastCRLF == 2)
			{
				endOfMsg = 1;
				break;
			}
			fLastCRLF = tmpPtr;
		}
		++tmpPtr;
	}

	if (!endOfMsg)
	{
		WARNING_TRACE("Bad endOfMsg!!! DON'T worry,just drop it\n");
		//SS_SYSLOG(LOG_WARNING,  (char *)"%s %d Bad endOfMsg!!!\n", __FUNCTION__, __LINE__);
		handleCmd_bad(clientSession, cseq);
		return;
	}

	if (!parseRTSPRequestString(clientSession->recvBuf, bytesRead,
				cmdName, sizeof(cmdName),
				urlPreSuffix, sizeof(urlPreSuffix),
				urlSuffix, sizeof(urlSuffix),
				cseq, sizeof(cseq)))
	{
		if (clientSession->streamingMode == RTP_TCP)
		{
			if (clientSession->recvBuf[0] == '$')
			{
				if (bytesRead == 1)
				{
					clientSession->Rtcp_Accept_Flag = 1;
				}
				else
				{
					gettimeofday(&timeNow,NULL);
					//DBG("!!!! 2 incomingConnectionHandlerClient 1\n");
					clientSession->rtcpKeepAliveTime = timeNow;
					keepaliveflag = 1;
				}
			}
			else
			{
				if (!clientSession->HttpFlag)
				{
					if (clientSession->Rtcp_Accept_Flag)
					{
						clientSession->Rtcp_Accept_Flag = 0;
						gettimeofday(&timeNow,NULL);
						//DBG("!!!! 3 incomingConnectionHandlerClient 1\n");
						clientSession->rtcpKeepAliveTime = timeNow;
						keepaliveflag = 1;
					}
					else
					{
						//ERR("Bad Rtsp Cmd!!! Line:%d\n",__LINE__);
						handleCmd_bad(clientSession, cseq);
						if(clientSession->bPlaySuccess == 0)
						{
							clientSession->bIsActive = -1;
							BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
						}
					}
				}
				else
				{
					clientSession->Http_Error_Flag = 1;
				}
			}
		}
		else
		{
			ERR("Bad Rtsp Cmd!!! Destroy\n");
			handleCmd_bad(clientSession, cseq);
			if(!clientSession->HttpFlag)
			{
				clientSession->bIsActive = -1;
				BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
			}
			else
				clientSession->Http_Error_Flag = 1;
		}
		return ;
	}
	else
	{
		MAGENTA_TRACE("cmdName=%s,urlPreSuffix=%s,urlSuffix=%s,cseq=%s\n",cmdName,urlPreSuffix,urlSuffix,cseq);
		sprintf(clientSession->streamName,urlSuffix);
		if (strcmp(cmdName, "OPTIONS") == 0)
		{
			handleCmd_OPTIONS(clientSession, cseq);
		}
		else if (strcmp(cmdName, "DESCRIBE") == 0)
		{
			handleCmd_DESCRIBE(clientSession, cseq, urlSuffix);
		}
		else if (strcmp(cmdName, "SETUP") == 0)
		{
			handleCmd_SETUP(clientSession, cseq, urlPreSuffix, urlSuffix);
		}
		else if (strcmp(cmdName, "TEARDOWN") == 0|| strcmp(cmdName, "PLAY") == 0
				|| strcmp(cmdName, "PAUSE") == 0|| strcmp(cmdName, "GET_PARAMETER") == 0
				|| strcmp(cmdName, "SET_PARAMETER") == 0)
		{
			handleCmd_withinSession(clientSession,cmdName, urlPreSuffix, urlSuffix, cseq);
		}
#if HIK_VERSION
		else if (strcmp(cmdName, "HEARTBEAT")==0)
		{
			handleCmd_HEARTBEAT(clientSession, cseq);
		}
#endif
		else
		{
			if (!clientSession->HttpFlag)
			{
				handleCmd_notSupported(clientSession,cseq);
				//SS_SYSLOG(LOG_ERR,  (char *)"RTSP recv invailed cmd:%s\n", cmdName);
				return;
			}
			else
				clientSession->Http_Error_Flag = 1;
		}
	}

	MAGENTA_TRACE("sock=%d,sendBuf=%s\n",clientSession->sock,clientSession->sendBuf);
	ret = comm_tcp_write(clientSession->sock,clientSession->sendBuf, strlen(clientSession->sendBuf),g_Env.fmaxDelayTime);
	//ERR("ret = %d\n",ret);
	if(ret <= 0&&errno != EINTR && errno != EAGAIN)
	{
		if (!clientSession->HttpFlag)
			clientSession->bIsActive = -1;
		else
			clientSession->Http_Error_Flag = 1;
		BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
		return;
	}
	if(clientSession->HttpFlag&&clientSession->bPlaySuccess)
	{
		g_Env.rtspSever->clientNum++;
	}
}


static int rtp_write(char *buf, int bufLen, int channle,int frametype,int mode, int start)
{
	int ret = -1;
	struct sockaddr rtpaddr;
	int rtpsocket;
	int to = g_Env.fmaxDelayTime;

	ClientSession *tempClientSession = NULL;
	for(int i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(g_Env.rtspSever->client[i]);
		//MAGENTA_TRACE("tempClientSession=%p,streamingMode=%d,mode=%d\n",tempClientSession,tempClientSession->streamingMode,mode);
		if(tempClientSession->bPlaySuccess == 0||
			(g_Env.rtspSever->bMediaType == 0&&MEDIA_TYPE == tempClientSession->media_stream_type)||
			(g_Env.rtspSever->bMediaType == 1&&g_Env.rtspSever->streamType != tempClientSession->bUseMinStream)
			||tempClientSession->streamingMode != mode)
		{
			continue;
		}
		if(tempClientSession->streamingMode == RTP_TCP)
		{
			rtpsocket = tempClientSession->sock;
			//SUCCESS_TRACE("bMediaType=%d,streamType=%d,media_stream_type=%d\n",g_Env.rtspSever->bMediaType,g_Env.rtspSever->streamType,tempClientSession->media_stream_type);
			ret = comm_tcp_write(rtpsocket,buf, bufLen,to);
			if(ret <= 0)
			{
				if(errno != EINTR && errno != EAGAIN)
				{
					if (!tempClientSession->HttpFlag)
						tempClientSession->bIsActive = -1;
					else
						tempClientSession->Http_Error_Flag = 1;
					BLUE_TRACE("tempClientSession->bIsActive=%d\n",tempClientSession->bIsActive);
				}
				else if(ret <= 0)
				{
					//��ʼͳ������
					tempClientSession->cursendstatus = 3;
					ERR("send failed,start the Network Traffic Statistics!,cursendstatus=%d\n",tempClientSession->cursendstatus);
				}
			}
		}
		else
		{
			//BLUE_TRACE("tempClientSession=%p,streamingMode=%d,mode=%d\n",tempClientSession,tempClientSession->streamingMode,mode);
			if (gRtspFamily)
				comm_make_sockAddr6((struct sockaddr_in6*)&rtpaddr, tempClientSession->destinationAddressStr, tempClientSession->clientRTPPortNum[channle]);
			else
				comm_make_sockAddr((struct sockaddr_in*)&rtpaddr, tempClientSession->destinationAddressStr, tempClientSession->clientRTPPortNum[channle]);

			rtpsocket = tempClientSession->rtpSocket[channle];
			ret = comm_udp_write(rtpsocket, buf, bufLen, &rtpaddr);
		}
	}
	for(int i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = g_Env.rtspSever->pHttp_session[i];
		if(NULL == tempClientSession)
			continue;
		if(tempClientSession->bPlaySuccess == 0||
			(g_Env.rtspSever->bMediaType == 0&&MEDIA_TYPE == tempClientSession->media_stream_type)||
			(g_Env.rtspSever->bMediaType == 1&&g_Env.rtspSever->streamType != tempClientSession->bUseMinStream)
			||tempClientSession->streamingMode != mode)
		{
			continue;
		}
		if(tempClientSession->streamingMode == RTP_TCP)
		{

			rtpsocket = tempClientSession->sock;
			//SUCCESS_TRACE("bMediaType=%d,streamType=%d,media_stream_type=%d\n",g_Env.rtspSever->bMediaType,g_Env.rtspSever->streamType,tempClientSession->media_stream_type);
			ret = comm_tcp_write(rtpsocket,buf, bufLen,to);
			if(ret <= 0)
			{
				if(errno != EINTR && errno != EAGAIN)
				{
					if (!tempClientSession->HttpFlag)
						tempClientSession->bIsActive = -1;
					else
						tempClientSession->Http_Error_Flag = 1;
					BLUE_TRACE("tempClientSession->bIsActive=%d\n",tempClientSession->bIsActive);
				}
				else if(ret <= 0)
				{
					tempClientSession->cursendstatus = 3;
					ERR("send failed,start the Network Traffic Statistics!,cursendstatus=%d\n",tempClientSession->cursendstatus);
				}
			}
		}
		else
		{
			if (gRtspFamily)
				comm_make_sockAddr6((struct sockaddr_in6*)&rtpaddr, tempClientSession->destinationAddressStr, tempClientSession->clientRTPPortNum[channle]);
			else
				comm_make_sockAddr((struct sockaddr_in*)&rtpaddr, tempClientSession->destinationAddressStr, tempClientSession->clientRTPPortNum[channle]);

			rtpsocket = tempClientSession->rtpSocket[channle];
			ret = comm_udp_write(rtpsocket, buf, bufLen, &rtpaddr);
		}
	}
	return ret;
}

static int nal_send_h265_video(ClientSession *clientSession, char *buf, int nallen, int blast,DWORD pts,int frametype,int mode)
{
	int sendLen = 0;
	int tempLen = 0;
	int fuNum = 0;
	int ret = 1;
	int channle = 0;
	int fuHeaderLen  = sizeof(H265FU_ADef);
	int rtpHeaderLen = sizeof(RTP_header);
	int dollarLen    = sizeof(RTP_over_tcp_header);
	H265FU_ADef *stFU_A = NULL;
	RTP_header *stRtpHeader = NULL;
	RTP_over_tcp_header *dollar = NULL;
	Rtsp_av_attr *AvAttr = NULL;
	AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;
	if(AvAttr == NULL)
	{
		return -1;
	}

	if(mode == RTP_TCP)
	{
		if (nallen + rtpHeaderLen + dollarLen <= g_Env.mtu)
		{
			dollar = (RTP_over_tcp_header *)(buf-rtpHeaderLen-dollarLen);
			stRtpHeader = (RTP_header *)(buf-rtpHeaderLen);
		}
		else
		{
			dollar = (RTP_over_tcp_header *)(buf-rtpHeaderLen-dollarLen-fuHeaderLen+2);
			stRtpHeader = (RTP_header *)(buf-rtpHeaderLen-fuHeaderLen+2);
			stFU_A = (H265FU_ADef *)(buf-fuHeaderLen+2);
		}
		dollar->dollar = '$';
		dollar->channelId = clientSession->rtpChannelId[0];
		stRtpHeader->version    = RTP_VERSION;
		stRtpHeader->csrc_len   = 0;
		stRtpHeader->extension  = 0;
		stRtpHeader->padding    = 0;
		stRtpHeader->payload    = AvAttr->videoPt;
		stRtpHeader->timestamp  = pts;
		stRtpHeader->ssrc       = htonl(clientSession->ssrc[0]);
		if(nallen + rtpHeaderLen + dollarLen <= g_Env.mtu)
		{
			stRtpHeader->seq_no = htons(clientSession->seq[0]++);
			stRtpHeader->marker = blast;
			sendLen             = nallen+rtpHeaderLen+dollarLen;
			dollar->packetSize  = htons(sendLen-dollarLen);
			ret = rtp_write(buf-rtpHeaderLen-dollarLen, sendLen, channle,frametype,mode,0);
			if(ret < 0)
				return ret;
		}
		else
		{
			char tmp_byte = buf[0];
			tempLen = rtpHeaderLen + dollarLen + fuHeaderLen;
			stFU_A->stFUIndicator.F = 0;
			stFU_A->stFUIndicator.payloadhdr = 49;
			stFU_A->stFUIndicator.LayerId = 0;
			stFU_A->stFUIndicator.TID = 1;
			stFU_A->stFUHeader.Type = (tmp_byte & 0x7e)>>1;
			stFU_A->stFUHeader.E = 0;
			stFU_A->stFUHeader.S = 0;
			buf += tempLen+2;
			while(nallen > 0)
			{
				sendLen = 0;
				if(fuNum == 0)
				{
					nallen -= 2;
					fuNum   = 1;
					stFU_A->stFUHeader.S = 1;
					stFU_A->stFUHeader.E = 0;
				}
				else
				{
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 0;
				}
				stRtpHeader->seq_no = htons(clientSession->seq[0]++);
				if(nallen + rtpHeaderLen + dollarLen + fuHeaderLen <= g_Env.mtu)
				{
					stRtpHeader->marker = blast;
					sendLen = tempLen+nallen;
					dollar->packetSize = htons(sendLen-dollarLen);
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 1;
					nallen = 0;
				}
				else
				{
					stRtpHeader->marker = 0;
					dollar->packetSize  = htons(g_Env.mtu-dollarLen);
					sendLen = g_Env.mtu;
					nallen -= g_Env.mtu - tempLen;
				}
				memcpy(buf, dollar, tempLen);
				ret = rtp_write(buf, sendLen, channle,frametype,mode,stFU_A->stFUHeader.S);
				if(ret < 0)
					return ret;
				buf += sendLen-tempLen;
			}
		}
	}
	else
	{
		dollarLen = 0;
		if (nallen + rtpHeaderLen + dollarLen <= g_Env.mtu)
		{
			dollar = (RTP_over_tcp_header *)(buf+headerSize-rtpHeaderLen-dollarLen);
			stRtpHeader = (RTP_header *)(buf+headerSize-rtpHeaderLen);
		}
		else
		{
			dollar = (RTP_over_tcp_header *)(buf+headerSize-rtpHeaderLen-dollarLen-fuHeaderLen+2);
			stRtpHeader = (RTP_header *)(buf+headerSize-rtpHeaderLen-fuHeaderLen+2);
			stFU_A = (H265FU_ADef *)(buf+headerSize-fuHeaderLen+2);
		}
		stRtpHeader->version    = RTP_VERSION;
		stRtpHeader->csrc_len   = 0;
		stRtpHeader->extension  = 0;
		stRtpHeader->padding    = 0;
		stRtpHeader->payload    = AvAttr->videoPt;
		stRtpHeader->timestamp  = pts;
#if HIK_VERSION
		stRtpHeader->ssrc		= htonl(0x55667788);
#else
		stRtpHeader->ssrc       = htonl(clientSession->ssrc[0]);
#endif
		if(nallen + rtpHeaderLen + dollarLen <= g_Env.mtu)
		{
			stRtpHeader->seq_no = htons(clientSession->seq[0]++);
			stRtpHeader->marker = blast;
			sendLen             = nallen+rtpHeaderLen+dollarLen;
			ret = rtp_write(buf+headerSize-rtpHeaderLen-dollarLen, sendLen, channle,0,RTP_UDP,0);
			if(ret < 0)
				return ret;
		}
		else
		{
			char tmp_byte = buf[headerSize];
			tempLen = rtpHeaderLen + dollarLen + fuHeaderLen;
			stFU_A->stFUIndicator.F = 0;
			stFU_A->stFUIndicator.payloadhdr = 49;
			stFU_A->stFUIndicator.LayerId = 0;
			stFU_A->stFUIndicator.TID = 1;
			stFU_A->stFUHeader.Type = (tmp_byte & 0x7e)>>1;
			stFU_A->stFUHeader.E = 0;
			stFU_A->stFUHeader.S = 0;
			buf += headerSize-tempLen+2;
			while(nallen > 0)
			{
				sendLen = 0;
				if(fuNum == 0)
				{
					nallen -= 2;
					fuNum   = 1;
					stFU_A->stFUHeader.S = 1;
					stFU_A->stFUHeader.E = 0;
				}
				else
				{
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 0;
				}
				stRtpHeader->seq_no = htons(clientSession->seq[0]++);
				if(nallen + rtpHeaderLen + dollarLen + fuHeaderLen <= g_Env.mtu)
				{
					stRtpHeader->marker = blast;
					sendLen = tempLen+nallen;
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 1;
					nallen = 0;
				}
				else
				{
					stRtpHeader->marker = 0;
					sendLen = g_Env.mtu;
					nallen -= g_Env.mtu - tempLen;
				}
				memcpy(buf, dollar, tempLen);
				ret = rtp_write(buf, sendLen, channle,0,RTP_UDP,0);
				if(ret < 0)
					return ret;
				buf += sendLen-tempLen;
			}
		}
	}

	return 1;
}

static int nal_send_video(ClientSession *clientSession, char *buf, int nallen, int blast,DWORD pts,int frametype,int mode)
{
	int sendLen = 0;
	int tempLen = 0;
	int fuNum = 0;
	int ret = 1;
	int channle = 0;
	int fuHeaderLen  = sizeof(FU_ADef);
	int rtpHeaderLen = sizeof(RTP_header);
	int dollarLen    = sizeof(RTP_over_tcp_header);
	FU_ADef *stFU_A = NULL;
	RTP_header *stRtpHeader = NULL;
	RTP_over_tcp_header *dollar = NULL;

	Rtsp_av_attr *AvAttr = NULL;
	AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;

	int iMtu = g_Env.mtu;

	if(AvAttr == NULL)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"avattr error line:%d\n",__LINE__);
		return -1;
	}

	if(mode == RTP_TCP)
	{
		if (nallen + rtpHeaderLen + dollarLen <= iMtu)
		{
			dollar = (RTP_over_tcp_header *)(buf+headerSize-rtpHeaderLen-dollarLen);
			stRtpHeader = (RTP_header *)(buf+headerSize-rtpHeaderLen);
		}
		else
		{
			dollar = (RTP_over_tcp_header *)(buf+headerSize-rtpHeaderLen-dollarLen-fuHeaderLen+1);
			stRtpHeader = (RTP_header *)(buf+headerSize-rtpHeaderLen-fuHeaderLen+1);
			stFU_A = (FU_ADef *)(buf+headerSize-fuHeaderLen+1);
		}
		dollar->dollar = '$';
		dollar->channelId = clientSession->rtpChannelId[0];

		stRtpHeader->version    = RTP_VERSION;
		stRtpHeader->csrc_len   = 0;
		stRtpHeader->extension  = 0;
		stRtpHeader->padding    = 0;
		stRtpHeader->payload    = AvAttr->videoPt;
		stRtpHeader->timestamp  = pts;
		stRtpHeader->ssrc       = htonl(clientSession->ssrc[0]);

		if(nallen + rtpHeaderLen + dollarLen <= iMtu)
		{
			stRtpHeader->seq_no = htons(clientSession->seq[0]++);
			stRtpHeader->marker = blast;
			sendLen             = nallen+rtpHeaderLen+dollarLen;
			dollar->packetSize  = htons(sendLen-dollarLen);

			ret = rtp_write(buf+headerSize-rtpHeaderLen-dollarLen, sendLen, channle,frametype,mode,0);
			if(ret < 0)
			{
				return ret;
			}
		}
		else
		{
			char tempBuff[1460] = {0};
			char tmp_byte = buf[headerSize];
			tempLen = rtpHeaderLen + dollarLen + fuHeaderLen;

			stFU_A->stFUIndicator.F = tmp_byte & 0x80;
			stFU_A->stFUIndicator.NRI = (tmp_byte & 0x60) >> 5;
			stFU_A->stFUIndicator.TYPE = 28;
			stFU_A->stFUHeader.Type = tmp_byte & 0x1f;
			stFU_A->stFUHeader.R = 0;
			stFU_A->stFUHeader.E = 0;
			stFU_A->stFUHeader.S = 0;
			buf += headerSize-tempLen+1;

			while(nallen > 0)
			{
				sendLen = 0;
				if(fuNum == 0)
				{
					nallen -= 1;
					fuNum   = 1;
					stFU_A->stFUHeader.S = 1;
					stFU_A->stFUHeader.E = 0;
				}
				else
				{
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 0;
				}

				stRtpHeader->seq_no = htons(clientSession->seq[0]++);

				if(nallen + rtpHeaderLen + dollarLen + fuHeaderLen <= iMtu)
				{
					stRtpHeader->marker = blast;
					sendLen = tempLen+nallen;
					dollar->packetSize = htons(sendLen-dollarLen);
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 1;
					nallen = 0;
				} else {
					stRtpHeader->marker = 0;
					dollar->packetSize  = htons(iMtu-dollarLen);
					sendLen = iMtu;
					nallen -= iMtu - tempLen;
				}
				memcpy(buf, dollar, tempLen);
				memcpy(tempBuff, buf, sendLen);
				
				ret = rtp_write(tempBuff, sendLen, channle,frametype,mode,stFU_A->stFUHeader.S);
				if(ret < 0)
				{
					return ret;
				}
				buf += sendLen-tempLen;
			}

		}
	}
	else
	{
		//MAGENTA_TRACE("clientSession=%p,streamingMode=%d\n",clientSession,clientSession->streamingMode);
		if (nallen + rtpHeaderLen <= g_Env.mtu) {
			stRtpHeader = (RTP_header *)(buf+headerSize-rtpHeaderLen);
		} else {
			stRtpHeader = (RTP_header *)(buf+headerSize-rtpHeaderLen-fuHeaderLen+1);
			stFU_A = (FU_ADef *)(buf+headerSize-fuHeaderLen+1);
		}
		stRtpHeader->version    = RTP_VERSION;
		stRtpHeader->csrc_len   = 0;
		stRtpHeader->extension  = 0;
		stRtpHeader->padding    = 0;
		stRtpHeader->payload    = AvAttr->videoPt;
		stRtpHeader->timestamp  = pts;
		stRtpHeader->ssrc       = htonl(clientSession->ssrc[0]);

		if(nallen + rtpHeaderLen <= g_Env.mtu) {
			stRtpHeader->seq_no = htons(clientSession->seq[0]++);
			stRtpHeader->marker = blast;
			sendLen             = nallen+rtpHeaderLen;

			ret = rtp_write(buf+headerSize-rtpHeaderLen, sendLen, channle,0,RTP_UDP,0);
			if(ret < 0)
				return ret;
		} else {
			char tmp_byte = buf[headerSize];
			tempLen = rtpHeaderLen + fuHeaderLen;
			stFU_A->stFUIndicator.F = tmp_byte & 0x80;
			stFU_A->stFUIndicator.NRI = (tmp_byte & 0x60) >> 5;
			stFU_A->stFUIndicator.TYPE = 28;
			stFU_A->stFUHeader.Type = tmp_byte & 0x1f;
			stFU_A->stFUHeader.R = 0;
			stFU_A->stFUHeader.E = 0;
			stFU_A->stFUHeader.S = 0;
			buf += headerSize-tempLen+1;

			while(nallen > 0) {
				sendLen = 0;
				if(fuNum == 0) {
					nallen -= 1;
					fuNum   = 1;
					stFU_A->stFUHeader.S = 1;
					stFU_A->stFUHeader.E = 0;
				} else {
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 0;
				}

				stRtpHeader->seq_no = htons(clientSession->seq[0]++);

				if(nallen + rtpHeaderLen + fuHeaderLen <= g_Env.mtu) {
					stRtpHeader->marker = blast;
					sendLen = tempLen+nallen;
					stFU_A->stFUHeader.S = 0;
					stFU_A->stFUHeader.E = 1;
					nallen = 0;
				} else {
					stRtpHeader->marker = 0;
					sendLen = g_Env.mtu;
					nallen -= g_Env.mtu - tempLen;
				}
				memcpy(buf, stRtpHeader, tempLen);
				ret = rtp_write(buf, sendLen, channle,0,RTP_UDP,0);
				if(ret < 0)
					return ret;
				buf += sendLen-tempLen;
			}
		}
	}
	return 1;
}

static int nal_send_audio(ClientSession *clientSession, char *buf, int buflen, int blast,DWORD pts,int mode)
{
	int ret = 1;
	int channle = 1;
	int sendLen = 0;
	int rtpHeaderLen = sizeof(RTP_header);
	int dollarLen = sizeof(RTP_over_tcp_header);
	RTP_header *stRtpHeader = NULL;
	RTP_over_tcp_header *dollar = NULL;

	Rtsp_av_attr *AvAttr = NULL;
	AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;

	if(AvAttr == NULL)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"avattr error line:%d\n",__LINE__);
		return -1;
	}

	if(mode == RTP_TCP) {
		dollar = (RTP_over_tcp_header *)(buf-rtpHeaderLen-dollarLen);
		stRtpHeader = (RTP_header *)(buf-rtpHeaderLen);
		buf -= rtpHeaderLen+dollarLen;

		dollar->dollar = '$';
		dollar->channelId = clientSession->rtpChannelId[1];
		stRtpHeader->version   = RTP_VERSION;
		stRtpHeader->csrc_len  = 0;
		stRtpHeader->extension = 0;
		stRtpHeader->padding   = 0;
		stRtpHeader->timestamp = pts;
		stRtpHeader->payload   = AvAttr->audioPt;
		stRtpHeader->ssrc   = htonl(clientSession->ssrc[1]);
		stRtpHeader->seq_no = htons(clientSession->seq[1]++);
		stRtpHeader->marker = blast;
		sendLen  = buflen+rtpHeaderLen;
		dollar->packetSize = htons(sendLen);
		sendLen += dollarLen;

		ret = rtp_write(buf, sendLen, channle,0,mode,0);
		if(ret < 0)
			return ret;
	}
	else {
		stRtpHeader = (RTP_header *)(buf-rtpHeaderLen);
		buf -= rtpHeaderLen;

		stRtpHeader->version    = RTP_VERSION;
		stRtpHeader->csrc_len   = 0;
		stRtpHeader->extension  = 0;
		stRtpHeader->padding    = 0;
		stRtpHeader->payload    = AvAttr->audioPt;
		stRtpHeader->timestamp  = pts;
		stRtpHeader->ssrc       = htonl(clientSession->ssrc[1]);
		stRtpHeader->seq_no = htons(clientSession->seq[1]++);
		stRtpHeader->marker = blast;
		sendLen             = buflen+rtpHeaderLen;

		ret = rtp_write(buf, sendLen, channle,0,mode,0);
		if(ret < 0)
			return ret;
	}
	return 1;
}

static int SendFrame(ClientSession *clientSession,DWORD pts,BYTE *jpeg_data, int len, BYTE type,
		BYTE typespec, int width, int height, int dri,BYTE q,BYTE *lqt, BYTE *cqt)
{
	RTP_header stRtpHeader;
	RTP_over_tcp_header dollar;
	int dollarLen = sizeof(RTP_over_tcp_header);

	struct jpeghdr jpghdr,jpghdr_off;
	struct jpeghdr_rst rsthdr;

	struct jpeghdr_qtable qtblhdr;
	char  packet_buf[1500] = {0};
	 char *ptr;
	int bytes_left = len;
	int data_len,ret;
	int channle = 0;

	DWORD   swapi = 0;
	DWORD   offtmp = 0;

	Rtsp_av_attr *AvAttr = NULL;
	AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;

	if(AvAttr == NULL)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"avattr error line:%d\n",__LINE__);
		return -1;
	}

	dollar.dollar = '$';
	dollar.channelId = clientSession->rtpChannelId[0];

	stRtpHeader.version   = RTP_VERSION;
	stRtpHeader.csrc_len  = 0;
	stRtpHeader.extension = 0;
	stRtpHeader.padding   = 0;
	stRtpHeader.timestamp = pts;
	stRtpHeader.payload   = AvAttr->videoPt;
	stRtpHeader.ssrc   = htonl(clientSession->ssrc[0]);

	jpghdr.tspec = typespec;
	jpghdr.off = 0;
	jpghdr.type = type | ((dri != 0) ? RTP_JPEG_RESTART : 0);
	jpghdr.q = q;
	jpghdr.width = width / 8;
	jpghdr.height = height / 8;


	if (dri != 0) {
		rsthdr.dri = dri;
		rsthdr.f = 1;
		rsthdr.l = 1;
		rsthdr.count = 0x3fff;
	}

	if (q >= 128) {
		qtblhdr.mbz = 0;
		qtblhdr.precision = 0;
		qtblhdr.length = htons(128);
	}

	while (bytes_left > 0)
	{
		stRtpHeader.marker = 0;
		if(clientSession->streamingMode == RTP_TCP)
		{
			ptr = packet_buf+dollarLen+RTP_HDR_SZ;
			memcpy(&jpghdr_off,&jpghdr,sizeof(jpghdr));
			offtmp= jpghdr_off.off;
			swapi = jpghdr_off.off;
			swapi = htonl(swapi);
			swapi = (swapi >> 8);
			jpghdr_off.off = swapi;
			memcpy(ptr, &jpghdr_off, sizeof(jpghdr_off));
			ptr += sizeof(jpghdr);

			jpghdr_off.off = offtmp;

			if (dri != 0)
			{
				memcpy(ptr, &rsthdr, sizeof(rsthdr));
				ptr += sizeof(rsthdr);
			}

			if (q >= 128 && jpghdr.off == 0)
			{
				memcpy(ptr, &qtblhdr, sizeof(qtblhdr));
				ptr += sizeof(qtblhdr);
				memcpy(ptr, lqt, 64);
				ptr += 64;
				memcpy(ptr, cqt, 64);
				ptr += 64;
			}

			data_len = g_Env.mtu - (ptr - packet_buf);
			if (data_len >= bytes_left)
			{
				data_len = bytes_left;
				stRtpHeader.marker = 1;
			}

			dollar.packetSize = htons((ptr - packet_buf) + data_len - dollarLen);
			stRtpHeader.seq_no = htons(clientSession->seq[0]++);

			memcpy(packet_buf, &dollar, dollarLen);
			memcpy(packet_buf+dollarLen, &stRtpHeader, RTP_HDR_SZ);
			memcpy(ptr, jpeg_data + jpghdr.off, data_len);
		}
		else
		{
			ptr = packet_buf+RTP_HDR_SZ;
			memcpy(&jpghdr_off,&jpghdr,sizeof(jpghdr));
			offtmp= jpghdr_off.off;
			swapi = jpghdr_off.off;
			swapi = htonl(swapi);
			swapi = (swapi >> 8);
			jpghdr_off.off = swapi;
			memcpy(ptr, &jpghdr_off, sizeof(jpghdr_off));

			ptr += sizeof(jpghdr);

			jpghdr_off.off = offtmp;

			if (dri != 0) {
				memcpy(ptr, &rsthdr, sizeof(rsthdr));
				ptr += sizeof(rsthdr);
			}

			if (q >= 128 && jpghdr.off == 0) {
				memcpy(ptr, &qtblhdr, sizeof(qtblhdr));
				ptr += sizeof(qtblhdr);
				memcpy(ptr, lqt, 64);
				ptr += 64;
				memcpy(ptr, cqt, 64);
				ptr += 64;
			}

			data_len = g_Env.mtu- (ptr- packet_buf);
			if (data_len >= bytes_left)
			{
				data_len = bytes_left;
				stRtpHeader.marker = 1;
			}

			stRtpHeader.seq_no = htons(clientSession->seq[0]++);

			memcpy(packet_buf, &stRtpHeader, RTP_HDR_SZ);
			memcpy(ptr, jpeg_data + jpghdr.off, data_len);
		}

		ret = rtp_write(packet_buf,(ptr - packet_buf) + data_len,channle,0,RTP_UDP,0);
		if(ret < 0)
			return ret;

		jpghdr.off += data_len;

		bytes_left -= data_len;
	}

	return 1;
}

static int getJpegAttr(char *frameBuf,int frameLen,
		BYTE **jpeg_data, int *len, BYTE *type,
		BYTE *typespec, int *width, int *height, int *dri,
		BYTE *q, BYTE *lqt, BYTE *cqt)
{
	char *buf_ptr,*buf_end;
	BYTE h,l;
	int start_code = 0;
	buf_ptr = frameBuf;
	buf_end = frameBuf+frameLen;
	*typespec= 0;
	while(buf_ptr < buf_end)
	{
		start_code = find_marker((BYTE **)&buf_ptr, (BYTE *)frameBuf+frameLen);
		switch(start_code)
		{
			case SOI:
				break;
			case DQT:
				*q = 255;
				buf_ptr += 3;
				memcpy(lqt, buf_ptr, 64);
				buf_ptr += 65;
				memcpy(cqt, buf_ptr, 64);
				buf_ptr += 64;
				break;
			case DHT:
				break;
			case SOF0:
				buf_ptr += 3;
				*type = 1;
				h = *buf_ptr++;
				l = *buf_ptr++;
				*height = h << 8 | l;
				h = *buf_ptr++;
				l = *buf_ptr++;
				*width = h << 8 | l;
			case SOF1:
				break;
			case SOF2:
				break;
			case SOF3:
				break;
			case SOF48:
				break;
			case LSE:
				break;
			case EOI:
				return 0;
			case SOS:
				*jpeg_data = (BYTE *)buf_ptr + 12;
				*len = (buf_end - buf_ptr)-12;
				return 1;
			case DRI:
				*dri = 1;
				break;
			case SOF5:
			case SOF6:
			case SOF7:
			case SOF9:
			case SOF10:
			case SOF11:
			case SOF13:
			case SOF14:
			case SOF15:
			case JPG:
				break;
		}
	}

	return 1;
}

static int  handle_rtp_send(ClientSession *clientSession,int framLen, DWORD timestamp,int bVideo,int mode)
{
	DWORD  rtpPts;
	int nalLen = 0;
	int nal_unit_type = 0;
	char audioBuf[1024] = {0};
	int	audioLen = 0;
	
	Rtsp_av_attr *AvAttr = NULL;
	AvAttr = g_Env.AvAttr + clientSession->nSrcChannel * 2 + clientSession->bUseMinStream;

	if(AvAttr == NULL)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"avattr error line:%d\n",__LINE__);
		return -1;
	}
	char *framBuf = NULL;
	if(mode == RTP_TCP)
		framBuf = g_Env.rtspSever->pTCPVideoBuf + headerSize;
	else
		framBuf = g_Env.rtspSever->pUDPVideoBuf + headerSize;
	framLen -= headerSize;

	if (bVideo == 1)
	{
		//if(timestamp == clientSession->lastPts[0])
			//rtpPts  = clientSession->rtptime[0];
		//else
			//rtpPts  = clientSession->rtptime[0] + H264_TIME_FREQUENCY*(timestamp-clientSession->lastPts[0]);
		//clientSession->lastPts[0] = timestamp;
		clientSession->rtptime[0] += timestamp;
		rtpPts = htonl(timestamp);

		if(strcmp(AvAttr->videoCodec,"H265")==0)
		{
			int curPos = 0;
			while(curPos < framLen)
			{
				nalLen = FindStartCode(&framBuf[curPos], framLen - curPos);
				if(nalLen < 0)
				{
					if(nal_send_h265_video(clientSession, &framBuf[curPos]-headerSize, framLen - curPos, 1, rtpPts, nal_unit_type,mode) < 0)
						return 0;
					break;
				}
				if(nal_unit_type != 0&& nal_unit_type != 1)
				{
					if(nal_send_h265_video(clientSession, &framBuf[curPos]-headerSize, nalLen, 0, rtpPts,nal_unit_type,mode) < 0)
						return 0;
				}

				if((nalLen + 4) >= framLen)
				{
					return 0;
				}
				curPos += nalLen + 4;
				nal_unit_type = (framBuf[curPos] & 0x7e)>>1;//framBuf[curPos] & 0x7e;
				if(nal_unit_type == 1 || nal_unit_type == 19)
				{
					if(nal_send_h265_video(clientSession, &framBuf[curPos]-headerSize, framLen - curPos, 1, rtpPts,nal_unit_type,mode) < 0)
						return 0;
					break;
				}
			}
		}
		else if(strcmp(AvAttr->videoCodec,"H264")==0)
		{
			#if 1
			int curPos = 0;
			fram_info_t *p_fram_info = (fram_info_t *)g_test_buff;
			nal_unit_type = (g_test_buff[headerSize+4]& 0x7e)>>1;
			BLUE_TRACE("framnum:%d fram_size:%d fram_type:%d nal_unit_type:%d\n",p_fram_info->framnum, p_fram_info->fram_size,p_fram_info->fram_type, nal_unit_type);
			
			if(nal_send_video(clientSession, g_test_buff, p_fram_info->fram_size, 1, rtpPts, nal_unit_type, mode) < 0)
			{
				return 0;
			}
			
			#else
			
			int curPos = 0;
			while(curPos < framLen)
			{
				nalLen = FindStartCode(&framBuf[curPos], framLen - curPos);
				if(nalLen < 0)
				{
					if(nal_send_video(clientSession, &framBuf[curPos]-headerSize, framLen - curPos, 1, rtpPts,nal_unit_type,mode) < 0)
					{
						return 0;
					}
					break;
				}

				if(nal_unit_type != 0)
				{
					if(nal_send_video(clientSession, &framBuf[curPos]-headerSize, nalLen, 0, rtpPts,nal_unit_type,mode) < 0)
					{
						return 0;
					}
				}

				curPos += nalLen + 4;
				nal_unit_type = framBuf[curPos] & 0x1f;
				if(nal_unit_type == 1 || nal_unit_type == 5)
				{
					if(nal_send_video(clientSession, &framBuf[curPos]-headerSize, framLen - curPos, 1, rtpPts,nal_unit_type,mode) < 0)
					{
						return 0;
					}
					break;

				}
			}
			#endif
		}
		else if(strcmp(AvAttr->videoCodec,"JPEG")==0)
		{
			BYTE *data = NULL;
			int len = 0;
			BYTE type = 0;
			BYTE typespec = 0;
			int width = 0;
			int height = 0;
			int dri = 0;
			BYTE q = 0;
			BYTE lqt[64]= {0};
			BYTE cqt[64]= {0};
			getJpegAttr(framBuf,framLen,
					&data, &len, &type,
					&typespec, &width, &height, &dri,
					&q, lqt, cqt);
			dri = 0;
			SendFrame(clientSession,rtpPts,data, len, type,typespec,
					width,height,dri,q, lqt, cqt);
		}
		return 1;
	}
	else
	{
		if(timestamp == clientSession->lastPts[1])
			rtpPts  = clientSession->rtptime[1];
		else
			rtpPts  = clientSession->rtptime[1] +
				AvAttr->audioSampleRate /1000 * (timestamp - clientSession->lastPts[1]);
		clientSession->lastPts[1] = timestamp;
		clientSession->rtptime[1] = rtpPts;
		rtpPts = htonl(rtpPts);
		if( strstr(AvAttr->audioCodec ,"G726") != NULL )
		{
			while(framLen > 0)
			{
				short *pp = (short *)framBuf;
				int len = pp[1] & 0x00ff;
				memcpy(audioBuf+audioLen+headerSize, framBuf + 4, len * 2);
				framLen -= 4 + len * 2;
				framBuf += 4 + len * 2;
				audioLen += len * 2;
			}

			if(nal_send_audio(clientSession, audioBuf + headerSize, audioLen, 1, rtpPts,mode) < 0)
				return 0;
		}
		else if(strcmp(AvAttr->audioCodec ,"MPEG4-GENERIC") == 0)
		{
			while(framLen > 0)
			{
				int	len = (framBuf[3] & 0x03) << 11;
				len |=  framBuf[4] << 3;
				len |=  (framBuf[5] & 0xe0) >> 5;
				memcpy(&audioBuf[4], framBuf + 7, len-7);
				audioBuf[0] = 0;
				audioBuf[1] = 16;
				audioBuf[2] = (len -7) >> 5;
				audioBuf[3] = ((len -7) & 0x1f) << 3;
				audioLen = len -7 + 4;
				if(nal_send_audio(clientSession, audioBuf, audioLen, 1, rtpPts,mode) < 0)
					return 0;
				framLen -= len;
				framBuf += len;
			}
		}
		else if(strcmp(AvAttr->audioCodec ,"AMR") == 0)
		{
			audioBuf[0] = 0xf0;
			framBuf += 1;
			audioBuf[1] = *framBuf & 0x7C;
			memcpy(&audioBuf[2], framBuf, framLen - 1);
			audioLen = framLen+1;

			if(nal_send_audio(clientSession, audioBuf, audioLen, 1, rtpPts,mode) < 0)
				return 0;
		}
		else
		{
			if(nal_send_audio(clientSession, framBuf, framLen, 1, rtpPts,mode) < 0)
				return 0;
		}
		return 1;
	}

	return 0;
}

int SS_Get_RtspTimeStart(void)
{
	return ngRtspTimeStartFlag;
}

int SS_Set_RtspTimeStart(int nflag)
{
	 ngRtspTimeStartFlag = nflag;

	 return 0;
}

int SS_Get_RtspTimeFlag(void)
{
	return ngRtspSetTimeFlag;
}

int SS_Set_RtspTimeFlag(int nflag)
{
	ngRtspSetTimeFlag = nflag;
	return 0;
}

/* status define as following
   00  ERROR_STATUS
   01  TCP_ESTABLISHED
   02  TCP_SYN_SENT
   03  TCP_SYN_RECV
   04  TCP_FIN_WAIT1
   05  TCP_FIN_WAIT2
   06  TCP_TIME_WAIT
   07  TCP_CLOSE
   08  TCP_CLOSE_WAIT
   09  TCP_LAST_ACK
   0A  TCP_LISTEN
   0B  TCP_CLOSING
*/
static int get_status_by_tcp_port(int report, int *txsize)
{
    char linebuf[1024];

    int no;
    int local_addr;
    int local_port;
    int rem_addr;
    int rem_port;
    int status;
    int tx_queue;
    int rx_queue;

    FILE *stream = fopen("/proc/net/tcp", "r");
    if (stream == NULL) {
        ERR("fopen error:%d\n", errno);
        return -1;
    }

    while(fgets(linebuf, sizeof(linebuf), stream) != NULL) {
        //DBG("read:%s", linebuf);
        if(sscanf(linebuf, "%d: %x:%x %x:%x %x %x:%x\n",
                  &no, &local_addr, &local_port, &rem_addr, &rem_port,
                  &status, &tx_queue, &rx_queue) != 8) {
            continue;
        }

        if(status != 1)
            continue;
        if(rem_port == report)
        {
        	if(txsize != NULL)
        		*txsize = tx_queue;
			 //DBG("%d: %x:%d %x:%d %x %d:%d,*txsize=%d\n",
               //no, local_addr, local_port, rem_addr, rem_port,
               //status, tx_queue, rx_queue,*txsize);
			break;
        }
    }
    fclose(stream);
    return 0;
}

void WriteDateHandler(void * instance,int Mask,int mode)
{
	ClientSession *clientSession = (ClientSession *)instance;
	if(clientSession == NULL)
		return;
	RtspServer *serverHand = g_Env.rtspSever;
	if(serverHand == NULL)
		return;
	//CYAN_TRACE("Mask=%d,clientSession=%p\n",Mask,clientSession);
	DWORD	timestamp = (DWORD)Mask;
	struct timeval 	timeNow = {0};
	struct timeval 	timeKeepAliveRemain = {0};
	gettimeofday(&timeNow, NULL);

	SS_Set_RtspTimeStart(1);
	if(SS_Get_RtspTimeFlag())
	{
		SS_Set_RtspTimeFlag(0);
		clientSession->rtcpKeepAliveTime = timeNow;
		clientSession->nKeepHBCount = 0;
	}

	timeKeepAliveRemain = timevalDec(timeNow, clientSession->rtcpKeepAliveTime);

	if(clientSession->bSCZRequestMulticast)
		CheckMultiMemberKeepAlive(clientSession->bUseMinStream,timeNow);
	if((abs(timeKeepAliveRemain.tv_sec * 1000 + timeKeepAliveRemain.tv_usec/1000) > 60000))
	{
		clientSession->nKeepHBCount++;
		if(clientSession->nKeepHBCount >= 10)
		{
			clientSession->nKeepHBCount = 0;
			if ((keepaliveflag == 2) && (clientSession->streamingMode == RTP_UDP) && (!clientSession->bSCZRequestMulticast))
			{
				clientSession->rtcpKeepAliveTime = timeNow;
				keepaliveflag = 0;
				return;
			}
		}
		else
		{
			clientSession->rtcpKeepAliveTime = timeNow;
			if (keepaliveflag == 0)
			{
				keepaliveflag = 2;
			}
			return;
		}

		if (clientSession->HttpFlag)
		{
			clientSession->Http_Error_Flag = 1;
		}
		else
		{
			if(clientSession->bSCZRequestMulticast)
			{
				DeleteAllSessionsMulti(clientSession->bUseMinStream);
			}
			else
			{
				clientSession->bIsActive = -1;
			}
		}
		return;
	}

	int streamType = g_Env.rtspSever->streamType;
	int MediaType = g_Env.rtspSever->bMediaType;
	int frameSize = g_Env.rtspSever->frameSize;
	RTSP_STREAM_PARAM *pVideoStream = &g_Env.rtspSever->bVideoStream[streamType];
	RTSP_STREAM_PARAM *pAudioStream = &g_Env.rtspSever->bAudioStream;
	if(pVideoStream->bFirst&&MediaType)
	{
		clientSession->lastPts[0] = timestamp;
		pVideoStream->bFirst = 0;
	}
	else if(pAudioStream->bFirst&&MediaType == 0)
	{
		clientSession->lastPts[1] = timestamp;
		pAudioStream->bFirst = 0;
	}
	if(handle_rtp_send(clientSession, frameSize,timestamp,MediaType,mode) <= 0)
	{
		ERR("handle_rtp_send error\n");
		if(errno != EAGAIN && errno != EINTR)
		{
			//clientSession->bIsActive = -1;
			BLUE_TRACE("clientSession->bIsActive=%d\n",clientSession->bIsActive);
		}
	}
	return;
}

static void SendVideoData(int streamType,DWORD timpstamp,int mode)
{
	//BLUE_TRACE("cdy clientNum:%d",g_Env.rtspSever->clientNum);
	RtspServer *prtspSer = g_Env.rtspSever;
	ClientSession *pSession = NULL;
	if(g_Env.rtspSever->clientNum > 0)
	{
		for(int i = 0;i<MAX_CLIENT_NUM;++i)
		{
			pSession = &prtspSer->client[i];
			if(pSession->bUseMinStream != streamType||pSession->bPlaySuccess == 0
				||pSession->streamingMode != mode)
			{
				continue;
			}
			//WARNING_TRACE("pSession->bUseMinStream=%d,pSession->bPlaySuccess=%d\n",pSession->bUseMinStream,pSession->bPlaySuccess);
			//CYAN_TRACE("g_Env.rtspSever->clientNum=%d,pSession=%p\n",g_Env.rtspSever->clientNum,pSession);
			//MAGENTA_TRACE("pSession=%p,firstframeflag=%d\n",pSession,pSession->firstframeflag);
			if(0 == pSession->firstframeflag)
			{
				if(g_Env.rtspSever->frametype != FRAME_TYPE_I)
				{
					continue;
				}
				pSession->firstframeflag = 1;
			}
			WriteDateHandler(pSession,timpstamp,mode);
			break;
		}
	}
	if(g_Env.rtspSever->clientNum > 0)
	{
		for(int i = 0;i<MAX_CLIENT_NUM;++i)
		{
			pSession = prtspSer->pHttp_session[i];
			if(!pSession)
			{
				continue;
			}
			if(pSession->bUseMinStream != streamType||pSession->bPlaySuccess == 0
				||pSession->streamingMode != mode)
			{
				continue;
			}
			//WARNING_TRACE("pSession->bUseMinStream=%d,pSession->bPlaySuccess=%d\n",pSession->bUseMinStream,pSession->bPlaySuccess);
			//CYAN_TRACE("g_Env.rtspSever->clientNum=%d,pSession=%p\n",g_Env.rtspSever->clientNum,pSession);
			if(0 == pSession->firstframeflag)
			{
				if(g_Env.rtspSever->frametype != FRAME_TYPE_I)
				{
					continue;
				}
				pSession->firstframeflag = 1;
			}
			WriteDateHandler(pSession,timpstamp,mode);
			break;
		}
	}
}

static void SendAudioData(DWORD timpstamp,int mode)
{
	RtspServer *prtspSer = g_Env.rtspSever;
	ClientSession *pSession = NULL;
	if(g_Env.rtspSever->clientNum > 0)
	{
		for(int i = 0;i<MAX_CLIENT_NUM;++i)
		{
			pSession = &prtspSer->client[i];
			if(pSession->media_stream_type == MEDIA_TYPE||pSession->bPlaySuccess == 0
				||pSession->streamingMode != mode)
			{
				continue;
			}
			WriteDateHandler(pSession,timpstamp,mode);
			break;
		}
	}
	if(g_Env.rtspSever->clientNum > 0)
	{
		for(int i = 0;i<MAX_CLIENT_NUM;++i)
		{
			pSession = prtspSer->pHttp_session[i];
			if(!pSession)
			{
				continue;
			}
			if(pSession->media_stream_type == MEDIA_TYPE||pSession->bPlaySuccess == 0
				||pSession->streamingMode != mode)
			{
				continue;
			}
			//WARNING_TRACE("pSession->bUseMinStream=%d,pSession->bPlaySuccess=%d\n",pSession->bUseMinStream,pSession->bPlaySuccess);
			//CYAN_TRACE("g_Env.rtspSever->clientNum=%d,pSession=%p\n",g_Env.rtspSever->clientNum,pSession);
			WriteDateHandler(pSession,timpstamp,mode);
			break;
		}
	}
}

void Handler_Sig(int no)
{
	return ;
}

static void Register_Signal(void)
{
	struct sigaction sig_st;
	static int nOnly = 0;
	if(nOnly == 0)
	{
		sigemptyset(&sig_st.sa_mask);
		sig_st.sa_flags = 0;
		sig_st.sa_handler = Handler_Sig;

		sigaction(SIGUSR1, &sig_st, NULL);
		nOnly = 1;
	}
}

static void Delete_HttpSession_Handle(int line, void *PNode)
{
	/*fprintf(stdout, "\nip %s port %d and port %d Rtp/Rtsp/Http disconnect......\n"
			"pthread_id %lu finished server\n",
			PNode->ip, PNode->get_port, PNode->post_port, PNode->clientsession->tid);*/
	//usleep(5500);
	G_RtpOverHttp_St *pNode = (G_RtpOverHttp_St *)PNode;
	shutdown(pNode->get_fd, SHUT_RDWR);
	shutdown(pNode->post_fd, SHUT_RDWR);
    if (-1 == close(pNode->get_fd)) {
           perror("close");
            fprintf(stderr, "%s\n", strerror(errno));
    }
    if (-1 == close(pNode->post_fd)) {
            perror("close");
            fprintf(stderr, "%s\n", strerror(errno));
    }
	g_Env.rtspSever->clientNum--;
	if(g_Env.rtspSever->clientNum<0)
		g_Env.rtspSever->clientNum = 0;

}

static void *doEventLoop(void* arg)
{
	//SS_SYSLOG(LOG_EMERG, (char *)"~~~~~~~~%s pid======%d\n", __func__, getpid());
	RtspServer	*rtspSer = (RtspServer	*)arg;
	if(NULL == rtspSer)
	{
		//SS_SYSLOG(LOG_EMERG,  (char *)"rtsp goto exits LINE:%d\n",__LINE__);
		return NULL;
	}
	struct timeval tv;
	fd_set readSet;
	//fd_set writeSet;
	int i;
	int selectResult;
	int maxfd = 0;
	rtsp_session_handle rtsphandle = {0};
	while(Com_Env.rtspTcpUdp_Is_Running)
	{
		tv.tv_sec  = 0;
		tv.tv_usec = 10000;
		maxfd = 0;
		FD_ZERO(&readSet);
		MERGEFD(rtspSer->fds[0],&readSet);
		MERGEFD(rtspSer->rtspSocket,&readSet);
		for(i = 0; i < MAX_CLIENT_NUM; ++i)
		{
			if(rtspSer->client[i].bUse)
			{
				MERGEFD(rtspSer->client[i].sock,&readSet);
				if(rtspSer->client[i].rtpSocket[0] > 0)
					MERGEFD(rtspSer->client[i].rtpSocket[0],&readSet);
				if(rtspSer->client[i].rtpSocket[1] > 0)
					MERGEFD(rtspSer->client[i].rtpSocket[1],&readSet);
			}
			if(rtspSer->pHttp_session[i])
			{
				//CYAN_TRACE("i=%d,clientsession=%p\n",i,rtspSer->pHttp_session[i]);
				MERGEFD(rtspSer->pHttp_session[i]->sock,&readSet);
				if(rtspSer->pHttp_session[i]->rtpSocket[0] > 0)
					MERGEFD(rtspSer->pHttp_session[i]->rtpSocket[0],&readSet);
				if(rtspSer->pHttp_session[i]->rtpSocket[1] > 0)
					MERGEFD(rtspSer->pHttp_session[i]->rtpSocket[1],&readSet);
			}
		}

		selectResult = select(maxfd+1, &readSet, NULL, NULL,&tv);

		if (selectResult > 0)
		{
			if (FD_ISSET(rtspSer->rtspSocket,&readSet))
			{
				incomingConnectionHandler(rtspSer,0);
			}
			for(i = 0;i<MAX_CLIENT_NUM;++i)
			{
				if(rtspSer->client[i].bUse)
				{
					if(FD_ISSET(rtspSer->client[i].sock,&readSet))
					incomingConnectionHandlerClient(&rtspSer->client[i],0);
					if(FD_ISSET(rtspSer->client[i].rtpSocket[0],&readSet))
						incomingConnectionHandlerClient(&rtspSer->client[i],1);
					if(FD_ISSET(rtspSer->client[i].rtpSocket[1],&readSet))
						incomingConnectionHandlerClient(&rtspSer->client[i],2);
				}
			}
		}
		DWORD timpstamp = 0;
		int MediaType = 0;
		RTSP_STREAM_PARAM *pStream = NULL;
		if(GetVideoSessionCount(0,RTP_TCP)+GetVideoSessionCount(0,RTP_UDP) > 0 
			&&Get_Video_Frame(0,&timpstamp) == 0)
		{
		   // BLUE_TRACE("cdy");
			MediaType = g_Env.rtspSever->bMediaType;
			pStream = &g_Env.rtspSever->bVideoStream[0];
			if(GetVideoSessionCount(0,RTP_TCP) > 0)
				SendVideoData(0,timpstamp,RTP_TCP);
			if(GetVideoSessionCount(0,RTP_UDP) > 0)
				SendVideoData(0,timpstamp,RTP_UDP);
			if(pStream->bFirst&&MediaType)
			{
				pStream->bFirst = 0;
			}
		}
		if(GetVideoSessionCount(1,RTP_TCP)+GetVideoSessionCount(1,RTP_UDP) > 0 
			&&Get_Video_Frame(1,&timpstamp) > 0)
		{
			MediaType = g_Env.rtspSever->bMediaType;
			pStream = &g_Env.rtspSever->bVideoStream[1];
			if(GetVideoSessionCount(1,RTP_TCP) > 0)
				SendVideoData(1,timpstamp,RTP_TCP);
			if(GetVideoSessionCount(1,RTP_UDP) > 0)
				SendVideoData(1,timpstamp,RTP_UDP);
			if(pStream->bFirst&&MediaType)
			{
				pStream->bFirst = 0;
			}
		}

		if(GetAudioSessionCount() > 0 && Get_Audio_Frame(&timpstamp) > 0)
		{
			MediaType = g_Env.rtspSever->bMediaType;
			pStream = &g_Env.rtspSever->bAudioStream;
			SendAudioData(timpstamp,RTP_TCP);
			SendAudioData(timpstamp,RTP_UDP);
			if(pStream->bFirst&&MediaType == 0)
			{
				pStream->bFirst = 0;
			}
		}
		ClientSession *tempClientSession = NULL;
		for(i = 0; i < MAX_CLIENT_NUM; i++)
		{
			tempClientSession = &(rtspSer->client[i]);
			if(tempClientSession->bIsActive == -1)
			{
				DestroyClientSession(tempClientSession);
			}
		}

		if(gRtspTimeSysn)
		{
			struct timeval timeNow;
			gettimeofday(&timeNow,NULL);

			for(i = 0; i < MAX_CLIENT_NUM; i++)
			{
				tempClientSession = &(rtspSer->client[i]);
				tempClientSession->nKeepHBCount = 0;
				if(tempClientSession->bUse)
				{
					tempClientSession->rtcpKeepAliveTime = timeNow;
					keepaliveflag = 0;
				}
			}
			gRtspTimeSysn = 0;
		}
	}

	DestroyRtspServer(__LINE__,g_Env.rtspSever);
	if(g_Env.AvAttr && Com_Env.RtspHttp_Is_Running == 0)
	{
		free(g_Env.AvAttr);
		g_Env.AvAttr= NULL;
		Com_Env.Is_Init_Rtspattr = 0;
	}
	SetRtspServerState(0);
	//SS_SYSLOG(LOG_EMERG,  (char *)"Exits DoEventLoop!!!!! LINE:%d\n",__LINE__);
	DBG("Exits DoEventLoop!!!!!\n");
	return NULL;
}

int gstmainvideocodeiflame(char *pmainsps, char *pmainpps, char *pmainsei, char *pmainvps,
								   int spslen, int ppslen, int seilen, int vpslen)
{
	memset(gstvideocodeiflame.gMainSPSbuf, 0, 128);
	memset(gstvideocodeiflame.gMainPPSbuf, 0, 128);
	memcpy(gstvideocodeiflame.gMainSPSbuf, pmainsps, 128);
	memcpy(gstvideocodeiflame.gMainPPSbuf, pmainpps, 128);
	gstvideocodeiflame.gMainSPSlen = spslen;
	gstvideocodeiflame.gMainPPSlen = ppslen;
	memset(gstvideocodeiflame.gMainSEIbuf, 0, 128);
	memset(gstvideocodeiflame.gMainVPSbuf, 0, 128);
	memcpy(gstvideocodeiflame.gMainSEIbuf, pmainsei, 128);
	memcpy(gstvideocodeiflame.gMainVPSbuf, pmainvps, 128);
	gstvideocodeiflame.gMainSEIlen = seilen;
	gstvideocodeiflame.gMainVPSlen = vpslen;

	return 0;
}

int gstminvideocodeiflame(char *pminsps, char *pminpps, char *pminsei, char *pminvps,
								   int spslen, int ppslen, int seilen, int vpslen)
{
	memset(gstvideocodeiflame.gMinSPSbuf, 0, 128);
	memset(gstvideocodeiflame.gMinPPSbuf, 0, 128);
	memcpy(gstvideocodeiflame.gMinSPSbuf, pminsps, 128);
	memcpy(gstvideocodeiflame.gMinPPSbuf, pminpps, 128);
	gstvideocodeiflame.gMinSPSlen = spslen;
	gstvideocodeiflame.gMinPPSlen = ppslen;
	memset(gstvideocodeiflame.gMinSEIbuf, 0, 128);
	memset(gstvideocodeiflame.gMinVPSbuf, 0, 128);
	memcpy(gstvideocodeiflame.gMinSEIbuf, pminsei, 128);
	memcpy(gstvideocodeiflame.gMinVPSbuf, pminvps, 128);
	gstvideocodeiflame.gMinSEIlen = seilen;
	gstvideocodeiflame.gMinVPSlen = vpslen;

	return 0;
}

int	setAvInfor(int nCh, int bMain, int bAudioOpen, char *audioCodec, int aduioSampleRate,
		int audioPt,char *videoCodec,int videoPt)
{
	Rtsp_av_attr *AvAttr = NULL;

	DBG("setAvInfor begin\n");
	DBG(" RTSP setAvInfor === nCh=%d,bMain=%d,videoPt=%d,audioPt=%d \n",nCh,bMain,videoPt,audioPt);
	AvAttr = g_Env.AvAttr + nCh * 2 + bMain;

	if(AvAttr == NULL)
		return -1;


	if(audioCodec == NULL || videoCodec == NULL || nCh >= g_Env.maxChn || nCh < 0 ||
			bMain > 1 || bMain < 0)
	{
		return -1;
	}

	snprintf(AvAttr->audioCodec,16,audioCodec);
	snprintf(AvAttr->videoCodec,16,videoCodec);
	AvAttr->audioSampleRate = aduioSampleRate;
	AvAttr->bAudioOpen = bAudioOpen;
	AvAttr->audioPt  	= audioPt;
	AvAttr->videoPt	= videoPt;
	DBG("setAvInfor end\n");

	return 0;
}

Rtsp_av_attr *getRtspAvInfor(int nCh, int bMain)
{
	Rtsp_av_attr *AvAttr = NULL;

	AvAttr = g_Env.AvAttr + nCh * 2 + bMain;

	return AvAttr;
}


int startRtspServer(int rtspPort, int bUserAuth, int bPassive, int mtu, int maxChn)
{
	gRtspFamily = 0;

	DBG("=========RTSPlib version is %s %s\n", __DATE__, __TIME__);
	DBG("startRtspServer rtspPort=%d,bUserAuth=%d,bPassive=%d,mtu=%d,maxChn=%d \n",rtspPort,bUserAuth,bPassive,mtu,maxChn);

	Register_Signal();
	//SS_SYSLOG(LOG_DEBUG,  (char *)"startRtspServer LINE:%d\n",__LINE__);

	g_Env.fmaxDelayTime = 5;
	if(mtu < 512 || mtu > 1460)
		g_Env.mtu = 1460;
	else
		g_Env.mtu = mtu;
	g_Env.maxChn = maxChn;
	g_Env.bPassive = bPassive;
	Com_Env.rtspTcpUdp_Is_Running = 1;
	g_Env.rtspServerThread = 0;
	
	if (g_Env.AvAttr == NULL && Com_Env.Is_Init_Rtspattr == 0)
	{
#if IPC_THIRD_STREAM
		g_Env.AvAttr = (Rtsp_av_attr *)malloc(3 * maxChn * sizeof(Rtsp_av_attr));
#else
		g_Env.AvAttr = (Rtsp_av_attr *)malloc(2 * maxChn * sizeof(Rtsp_av_attr));
#endif
		if(NULL == g_Env.AvAttr)
		{
			//SS_SYSLOG(LOG_EMERG, (char *)"mallo error line:%d\n",__LINE__);
			return -1;
		}
	}

	if(g_Env.AvAttr == NULL)
		return -1;

	sprintf(g_Env.filePath,"./");

	if(NULL == (g_Env.rtspSever = CreatRtspServer(rtspPort, bUserAuth)))
	{
		return -1;
	}
	
	if(g_Env.rtspSever->pTCPVideoBuf == NULL||g_Env.rtspSever->pUDPVideoBuf == NULL)
	{
		int maxFrameLen = 30;
		g_Env.rtspSever->maxVideoLen = maxFrameLen;
		g_Env.rtspSever->pTCPVideoBuf = (char *)malloc(maxFrameLen);
		g_Env.rtspSever->pUDPVideoBuf = (char *)malloc(maxFrameLen);
		if(g_Env.rtspSever->pTCPVideoBuf == NULL||g_Env.rtspSever->pUDPVideoBuf == NULL)
		{
			BLUE_TRACE("g_Env.rtspSever->pTCPVideoBuf=%p\n",g_Env.rtspSever->pTCPVideoBuf);
			return -1;
		}
	}
	
	g_Env.rtspSever->bVideoStream[0].bFirst = 1;
	g_Env.rtspSever->bVideoStream[1].bFirst = 1;
	g_Env.rtspSever->bVideoStream[2].bFirst = 1;
	g_Env.rtspSever->bAudioStream.bFirst = 1;
	sigset_t signal_mask;
	sigemptyset (&signal_mask);
	sigaddset (&signal_mask, SIGPIPE);
	int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if(rc != 0)
	{
		ERR("block sigpipe error\n");
	}

	if (pthread_create(&g_Env.rtspServerThread, NULL, doEventLoop,(void *)g_Env.rtspSever) != 0)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"create pthread error line:%d\n",__LINE__);
		return -1;
	}
	if (pthread_detach(g_Env.rtspServerThread) != 0)
	{
		ERR("pthread detached g_Env.rtspServerThread failed\n");
		return -1;
	}

	SetRtspServerState(1);
	return 1;
}

int startRtspServer6(int rtspPort, int bUserAuth, int bPassive, int mtu, int maxChn)
{
	int err;
	RtspServer *rtspSer = NULL;
	gRtspFamily = 1;
	DBG("=========ipv6 RTSPlib version is %s %s\n", __DATE__, __TIME__);
	DBG("RTSPLib Make On %s %s\n",__DATE__,__TIME__);
	DBG("startRtspServer6 rtspPort=%d,bUserAuth=%d,bPassive=%d,mtu=%d,maxChn=%d \n",rtspPort,bUserAuth,bPassive,mtu,maxChn);
	DBG("startRtspServer6 begin line = %d \n",__LINE__);
	Register_Signal();
	//SS_SYSLOG(LOG_DEBUG,  (char *)"startRtspServer6 LINE:%d\n",__LINE__);
	g_Env.fmaxDelayTime = 5;
	if(mtu <= 256)
		mtu = 1460-12;
	g_Env.mtu = mtu;
	g_Env.maxChn = maxChn;
	g_Env.bPassive = bPassive;
	Com_Env.rtspTcpUdp_Is_Running = 1;
	g_Env.rtspServerThread = 0;
	if (g_Env.AvAttr == NULL && Com_Env.Is_Init_Rtspattr == 0)
	{

		g_Env.AvAttr = (Rtsp_av_attr *)malloc(2 * maxChn * sizeof(Rtsp_av_attr));
		if(g_Env.AvAttr == NULL)
		{
			ERR("mallo error line:%d\n", __LINE__);
			return -1;
		}
	}
	if(g_Env.AvAttr == NULL) //2012.5.2 yj
		return -1;
	sprintf(g_Env.filePath,"./");
	rtspSer = CreatRtspServer(rtspPort, bUserAuth);
	if(rtspSer == NULL)
		return -1;
	g_Env.rtspSever = rtspSer;

	sigset_t signal_mask;
	sigemptyset (&signal_mask);
	sigaddset (&signal_mask, SIGPIPE);
	int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if(rc != 0)
	{
		ERR("block sigpipe error\n");
	}
	err = pthread_create(&(g_Env.rtspServerThread), NULL, doEventLoop, rtspSer);
	if(err != 0)
	{
		//SS_SYSLOG(LOG_EMERG, (char *)"create pthread error line:%d\n",__LINE__);
		return -1;
	}
	SetRtspServerState(1);
	return 1;
}
void stopRtspServer(void)
{
	//SS_SYSLOG(LOG_DEBUG,  (char *)"stopRtspServer LINE:%d\n",__LINE__);
	Com_Env.rtspTcpUdp_Is_Running = 0;
}

int rtsp_unicast_multicast(int nRtspSever,int bMutlicast,char *szMulticastIP,WORD nMainVideoPort,
	WORD nMainAudioPort,WORD nViceVideoPort,WORD nViceAudioPort,int nRes)
{
	struct in_addr	sin_addr;
	RtspServer		*pRtspServer = g_Env.rtspSever;

	if(pRtspServer== NULL)
		return 0;

	if(NULL== pRtspServer)
		return 0;

	pRtspServer->bMulticast = 0;
	if(bMutlicast)
	{
		if(NULL == szMulticastIP || !inet_aton(szMulticastIP, &sin_addr))
			return 0;

		snprintf(pRtspServer->szMulticastIP,16,szMulticastIP);

		pRtspServer->nVideoPort[0] = nMainVideoPort;
		pRtspServer->nVideoPort[1] = nViceVideoPort;

		pRtspServer->nAudioPort[0] = nMainAudioPort;
		pRtspServer->nAudioPort[1] = nViceAudioPort;
	}
	DBG("rtsp_unicast_multicast end\n");
	gRtspFamily = 0;
	return 1;
}
int	rtsp_unicast_multicast6(int nRtspSever,int bMutlicast,char *szMulticastIP,WORD nMainVideoPort,
	WORD nMainAudioPort,WORD nViceVideoPort,WORD nViceAudioPort,int nRes)
{
	struct in6_addr 	sin_addr;
	RtspServer		*pRtspServer = g_Env.rtspSever;

	if(pRtspServer== NULL)
		return 0;

	if(NULL== pRtspServer)
		return 0;
	pRtspServer->bMulticast = 0;//bMutlicast;
	if(bMutlicast)
	{
		if(NULL == szMulticastIP || inet_pton(AF_INET6, szMulticastIP, &sin_addr)<=0)
			return 0;
		snprintf(pRtspServer->szMulticastIP,48,szMulticastIP);
		pRtspServer->nVideoPort[0] = nMainVideoPort;
		pRtspServer->nVideoPort[1] = nViceVideoPort;
		pRtspServer->nAudioPort[0] = nMainAudioPort;
		pRtspServer->nAudioPort[1] = nViceAudioPort;
	}
	DBG("rtsp_unicast_multicast end\n");
	gRtspFamily = 1;
	return 1;
}

void sysnRtspHBTime(void)
{
	if(!GetRtspServerState())
		return;

	DBG("--------sysnRtspHBTime()----------\n");
	gRtspTimeSysn = 1;
}


void CheckMultiMemberKeepAlive(const int bUseMin,const struct timeval timeNow)
{
	static int nCount = 0;
	if(nCount<0)
		nCount = 0;
	if(nCount<750)
	{
		nCount++;
		return;
	}
	nCount = 0;
	//DBG("CheckMultiMemberKeepAlive\n");
	int				i = 0;
	ClientSession	* tempClientSession;
	RtspServer 		* serverHand = g_Env.rtspSever;

	if(serverHand == NULL)
		return;

	struct timeval timeKeepAliveRemain;
	for(i = 0; i < MAX_CLIENT_NUM; i++)
	{
		tempClientSession = &(serverHand->client[i]);
		if(tempClientSession->bUse == 1&&tempClientSession->bUseMinStream==bUseMin&&
			tempClientSession->bSCZRequestMulticast&&tempClientSession->nMultiClientNo!=1)
		{
			timeKeepAliveRemain = timevalDec(timeNow, tempClientSession->rtcpKeepAliveTime);
			if((abs(timeKeepAliveRemain.tv_sec * 1000000 + timeKeepAliveRemain.tv_usec) > 60000000))
			{
				if(tempClientSession->nKeepHBCount<0||tempClientSession->nKeepHBCount>=2)
					tempClientSession->nKeepHBCount = 0;
				tempClientSession->nKeepHBCount++;
				if(tempClientSession->nKeepHBCount == 2) //ͳ������
				{
					tempClientSession->nKeepHBCount = 0;
					tempClientSession->bIsActive = -1;
					BLUE_TRACE("tempClientSession->bIsActive=%d\n",tempClientSession->bIsActive);
				}
				else
				{
					//DBG("!!!! CheckMultiMemberKeepAlive\n");
					tempClientSession->rtcpKeepAliveTime = timeNow;
					keepaliveflag = 1;
					continue;
				}
			}
		}
	}

	return;
}


int GetRtspServerState()
{
	return nRtspIsRunning;
}

int SetRtspServerState(int nState)
{
	nRtspIsRunning = nState;
	return 0;
}

int SetRtspDescribeMultiState(int flag)
{
	gRtspMultiFlag = flag;
	return 0;
}



