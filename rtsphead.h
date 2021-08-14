#ifndef __RTSPHEAD_H_
#define __RTSPHEAD_H_
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/time.h>
#include "rtsptask.h"

#ifdef __cplusplus
extern "C" {
#endif
extern const char* const libServer;
typedef struct _rtsp_server RtspServer;

#ifndef BYTE
typedef unsigned char BYTE;
#endif

#ifndef WORD
typedef unsigned short WORD;
#endif

#ifndef DWORD
typedef unsigned int DWORD;
#endif

#ifndef UINT_MAX
#define UINT_MAX 0xffffffff
#endif

#ifndef PACKED
#define PACKED		__attribute__((packed, aligned(1)))
#endif

#define RTP_VERSION		2		
#define H264_TIME_FREQUENCY     90

#define MAX_CLIENT_NUM 8

typedef void UrlAnalysis(char* url,int *nCh, int *bMain);
typedef enum _StreamMode
{
	RTP_TCP,
	RTP_UDP,
	RAW_UDP
}StreamMode;

typedef enum STREAM_TYPE{
	AUDIO_TYPE = 1,
	MEDIA_TYPE,
	MIXED_TYPE
}STREAM_TYPE;

typedef struct _user_auth
{	
	char	fUserName[64];
	char	fPassWord[64];
	int		fIsMd5Auth;
}PACKED UserAuth;

typedef struct _client_session
{
	RtspServer			*ourServer;
	int 			  	sock;
	int			 		bUse;
	int					bIsActive;
	int					firstframeflag;
	int					bIsMulticast;
	int			  		bUseMinStream;
	int			  		bwifiFlag;
	int			  		nSrcChannel;
	DWORD				lastPts[2];
	struct timeval		rtcpKeepAliveTime;
	StreamMode 			streamingMode;
	int					mediaNum;
	int					trackId[2];
	char 				destinationAddressStr[64];
	DWORD				cseq;
	WORD 				clientRTPPortNum[2];
	WORD 				clientRTCPPortNum[2];
	WORD 				serverRTPPortNum[2];
	int					rtpSocket[2];
	DWORD 				rtpChannelId[2];
	unsigned long long  session;
	DWORD       		ssrc[2];
	WORD     			seq[2];
	DWORD       		rtptime[2];	
	char				streamName[32];
	char				sendBuf[4096];
	char				recvBuf[4096];
	int                 HttpFlag;
	int			 		Http_Error_Flag;
	int			 		Rtcp_Accept_Flag;
	int					Http_in_pipe;
	STREAM_TYPE        	media_stream_type;
	int				   	bSCZRequestMulticast;
	DWORD       		nMultiClientNo;
	int				   	bForMultiKeep;
	int				   	bPlaySuccess;

	int				   	nKeepHBCount;
	
	int				   	vlcconnect;	
	int				   	curcaltime;				
	int				   	lastcaltime;			
	int				   	socketsendbufsize;		
	int				   	sendgoodcount;			
	int				   	sendidlecount;			
	int				   	sendbadcount;			
	int				   	sendverybadcount;
	int				   	cursendstatus;			
	char 			   	nonce[32]; 
}PACKED ClientSession;

typedef struct
{
	int					type;
	void   				*pNode;
}rtsp_session_handle;

typedef struct RTSP_Stream_Param
{
	int					bFirst;
	DWORD				lastFrameNo;
	int					lastPos;
	int 				EnableFlag;
}RTSP_STREAM_PARAM;

struct _rtsp_server
{
	int					rtspPort;
	int					rtspSocket;
	int					clientNum;
	int					fIsUserAuth;
	UserAuth			fUserAuth;
	ClientSession		client[MAX_CLIENT_NUM];
	ClientSession		*pHttp_session[MAX_CLIENT_NUM];
	int					bMulticast;		
	char				szMulticastIP[16];	
	WORD				nVideoPort[2];	
	WORD				nAudioPort[2];	
	
	DWORD				nMultiClientNum[2];
	int					fds[2];
	char			 	*pTCPVideoBuf;
	char			 	*pUDPVideoBuf;
	int					maxVideoLen;
	int					frameSize;
	int					frametype;
	int					streamType; 
	int					bMediaType;
	RTSP_STREAM_PARAM	bVideoStream[3];
	RTSP_STREAM_PARAM	bAudioStream;
}PACKED; 

typedef struct _rtsp_av_attr
{
	int				audioSampleRate;
	int				bAudioOpen;
	int				audioPt;
	int				videoPt;
	char			audioCodec[16];
	char			videoCodec[16];
}Rtsp_av_attr;

typedef struct _rtsp_env
{
	RtspServer  	*rtspSever;
	int				bPassive;
	int				mtu;
	int 			maxChn;
	int				fmaxDelayTime;
	pthread_t 		rtspServerThread;
	Rtsp_av_attr	*AvAttr;
	UrlAnalysis		*pf_urlAnalysis;
	char			filePath[256];
}PACKED RtspEnv;

typedef struct _VIDEO_CODE_IFLAME_S
{
	char gMainSPSbuf[128];
	char gMainPPSbuf[128];
	char gMinSPSbuf[128];
	char gMinPPSbuf[128];
	int gMainSPSlen;
	int gMainPPSlen;
	int gMinSPSlen;
	int gMinPPSlen;
	char gMainSEIbuf[128];
	char gMainVPSbuf[128];
	char gMinSEIbuf[128];
	char gMinVPSbuf[128];
	int gMainSEIlen;
	int gMainVPSlen;
	int gMinSEIlen;
	int gMinVPSlen;

	char gThirdSPSbuf[128];
	char gThirdPPSbuf[128];
	int gThirdSPSlen;
	int gThirdPPSlen;
	char gThirdSEIbuf[128];
	char gThirdVPSbuf[128];
	int gThirdSEIlen;
	int gThirdVPSlen;
}PACKED VIDEO_CODE_IFLAME_S;


typedef struct  _RTP_header 
{
	BYTE csrc_len:4;   
	BYTE extension:1; 
	BYTE padding:1;	
	BYTE version:2;	

	BYTE payload:7;	
	BYTE marker:1;		
	WORD seq_no;		
	DWORD timestamp;		
	DWORD ssrc;			
}PACKED RTP_header;

typedef struct _RTP_over_tcp_header
{
	BYTE  dollar;
	BYTE  channelId;
	WORD packetSize;
}PACKED RTP_over_tcp_header;

typedef struct tagFUIndicator
{
	char TYPE : 5;		
	char NRI : 2;		
	char F : 1; 		
}PACKED FUIndicatorDef;

typedef struct tagFUHeader
{
	char Type : 5;		
	char R : 1; 		
	char E : 1; 		
	char S : 1; 		
}PACKED FUHeaderDef;

typedef struct tagFU_A
{
	FUIndicatorDef stFUIndicator;
	FUHeaderDef stFUHeader;
}PACKED FU_ADef;

typedef struct tagH265FUIndicator
{
	 short  F : 1; 	
	 short payloadhdr: 6;
	 short LayerId1 : 1;
	 short TID : 3;	
	 short LayerId : 5;	
}PACKED H265FUIndicatorDef;

typedef struct tagH265FUHeader
{
	 char Type : 6;			
	 char E : 1; 		
	 char S : 1; 	
}PACKED H265FUHeaderDef;

typedef struct tagH265FU_A
{
	H265FUIndicatorDef stFUIndicator;
	H265FUHeaderDef stFUHeader;
}PACKED H265FU_ADef;

#ifdef __cplusplus
}
#endif

#endif
