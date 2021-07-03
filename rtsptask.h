#ifndef __RTSPTASK_H_
#define __RTSPTASK_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "rtsphead.h"
#define RTSP_HDR_AUTHORIZATION		"Authorization"
typedef struct Rtsp_TcpUdp_Http_Comm{
	int  Is_Init_Rtspattr;     //rtsp/http and rtsp/tcp/udp can init g_Env  so use this variables can avoid it reinited 
	int  min_use_count[4];        //use in min media stream user count (include rtsp/http user and rtsp/tcp/udp user)
	int  Is_Enable_Min[4];        //if min media stream was enabled
	int  RtspHttp_Is_Running;  //rtsp/http running flag 
	int  rtspTcpUdp_Is_Running;//rtsp/tcp/udp running flag
	//int  Sem_Id;                 //semaphore identifier
}Rtsp_TcpUdp_Http_Comm;

extern Rtsp_TcpUdp_Http_Comm Com_Env;

int gstminvideocodeiflame(char *pminsps, char *pminpps, char *pminsei, char *pminvps,
								   int spslen, int ppslen, int seilen, int vpslen);
int gstmainvideocodeiflame(char *pmainsps, char *pmainpps, char *pmainsei, char *pmainvps,
								   int spslen, int ppslen, int seilen, int vpslen);
#if  IPC_THIRD_STREAM
int gstthirdvideocodeiflame(char *pmainsps, char *pmainpps, char *pmainsei, char *pmainvps,
								   int spslen, int ppslen, int seilen, int vpslen);
#endif
int setAvInfor(int nCh, int bMain, int bAudioOpen, char *audioCodec, int aduioSampleRate, int audioPt,char *videoCodec,int videoPt);
int startRtspServer(int rtspPort, int bUserAuth, int bPassive, int mtu, int maxChn);
int startRtspServer6(int rtspPort, int bUserAuth, int bPassive, int mtu, int maxChn);
void stopRtspServer();
int rtsp_unicast_multicast(int nRtspSever,int bMutlicast,char *szMulticastIP,unsigned short nMainVideoPort,unsigned short nMainAudioPort,unsigned short nViceVideoPort,unsigned short nViceAudioPort,int nRes);
int	rtsp_unicast_multicast6(int nRtspSever,int bMutlicast,char *szMulticastIP,unsigned short nMainVideoPort,unsigned short nMainAudioPort,unsigned short nViceVideoPort,unsigned short nViceAudioPort,int nRes);
void sysnRtspHBTime(void);
void incomingConnectionHandlerClient(void * instance, int Mask);
long long our_random64(void); 
void our_srandom(unsigned int x);
void WriteDateHandler(void * instance, int Mask, int mode);
void WifiHandlerStream(void * instance);
int av_base64_decode(unsigned char* out, const char *in, int out_length);
void sysnRtspHBTime(void);
int SetRtspDescribeMultiState(int flag);

extern int Intf_GetAudioFrame(int nChnNo,char *pFrameBuf,int nFrameBufSize,unsigned int nAudioFrmNo,unsigned int *nTrueFrmNo,int *nLastAudioPos);
extern int	Intf_GetVideoFrame(int nChnNo,int bSubChn,char *pFrameBuf,int nFrameBufSize,int bKeyFrame,int bLostLastestKey,unsigned int nVideoFrmNo,unsigned int *nRealFrmNo,unsigned int interMilliSecond,unsigned int preFrmTime,unsigned int *nowFrmTime,int *nLastVideoPos);
extern int  SS_PUB_EnableMinStream(int chn);
#if IPC_THIRD_STREAM_ENABLE
extern int  SS_PUB_EnableThirdStream(int chn);
extern int SS_PUB_GetEnableThirdStreamStat(int chn);
#endif
extern int  SS_PUB_SetRebootDVS(const char *filename, int line);
extern int  SS_PUB_DisEnableMinStream(int chn);
#if IPC_THIRD_STREAM_ENABLE
extern int  SS_PUB_DisEnableThirdStream(int chn);
#endif
extern int  SS_PUB_GetMaxFrameSize();	
extern int  SS_VENC_RequestIFrame(unsigned char  nCh, unsigned char  nMinEnc, unsigned char  nIFrameCount);
extern int SS_NETMAIN_CheckUser(const char *pUserName,const char *pPsw);
int SS_Get_RtspTimeStart(void);
int SS_Set_RtspTimeFlag(int nflag);
int GetRtspStreamNum(int stream);

#ifdef __cplusplus
}
#endif

#endif
