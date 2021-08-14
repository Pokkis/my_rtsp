#ifndef _QUEUE_H_
#define _QUEUE_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <pthread.h>
#include <stdio.h>

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

//公共的数据队列接口
typedef struct
{
    unsigned int front;
    unsigned int rear;
    pthread_mutex_t EnQueueLock; //进队列互斥锁
    pthread_mutex_t DeQueueLock; //出队列互斥锁
	unsigned int maxQueueSize;
    char *data;
} sequeue_data_t;

sequeue_data_t *CreateEmptyDataSequeue(int maxDataCount, int oneDataSize);
void DestroyDataSequeue(sequeue_data_t *queue);
int EmptyDataSequeue(sequeue_data_t *queue);
int FullDataSequeue(sequeue_data_t *queue);
int EnDataQueue(sequeue_data_t *queue, char *inData, int oneDataSize);
int DeDataQueue(sequeue_data_t *queue, char *outData, int oneDataSize);
int DeAllDataQueue(sequeue_data_t *queue);
unsigned int GetSequeueSize(sequeue_data_t *queue);
int EnDataQueue_Loop(sequeue_data_t *queue, char *inData, int oneDataSize);

#ifdef __cplusplus
}
#endif
#endif