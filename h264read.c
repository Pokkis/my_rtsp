#include "h264read.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include "queue.h"
#include "rtsptask.h"

#define MAXBUF 512*1024
#define SEND_FILE "./128x128.264"
#define WRITE_FILE "./test_out.h264"

typedef struct _h264_read_t
{
    int init_flag;
    int run_flag;
    pthread_t task_thd;
    sequeue_data_t *fram_queue;
    unsigned int fram_count;
}h264_read_t;

static h264_read_t g_h264_read;

static void *h264_read_thread(void *arg);
static void *h264_write_thread(void *arg);

static char* find_nal_start_code(char *buff, int n_read_len)
{
    if(NULL == buff || n_read_len < 4)
    {
        return NULL;
    }

    int i = 0;
    for(i = 0; i < n_read_len - 4; i++)
    {
        if(buff[i] == 0x00 && buff[i+1] == 0x00 && 
            buff[i+2] == 0x00 && buff[i+3] == 0x01)
        {
            return &buff[i];
        }
    }
    
    return NULL;
}

int h264_read_init()
{
    if(g_h264_read.init_flag)
    {
        return -1;
    }

    g_h264_read.init_flag = 1;
    g_h264_read.fram_queue = CreateEmptyDataSequeue(300, sizeof(fram_info_t));
    return 0;
    
}

int h264_read_start()
{
    if(g_h264_read.init_flag == 0)
    {
        return -1;
    }

    if(g_h264_read.run_flag)
    {
        return 0;
    }

    g_h264_read.run_flag = 1;

    if (pthread_create(&g_h264_read.task_thd, NULL, h264_read_thread, (void*)&g_h264_read.run_flag) != 0)
	{
		ERR("pthread_create h264_read_thread failed\n");
		return -1;
	}

	if (pthread_detach(g_h264_read.task_thd) != 0)
	{
		ERR("pthread detached h264_read_thread failed\n");
		return -1;
	}

#if 0
    pthread_t test_write_t;
    if (pthread_create(&test_write_t, NULL, h264_write_thread, (void*)&g_h264_read.run_flag) != 0)
	{
		ERR("pthread_create h264_read_thread failed\n");
		return -1;
	}

	if (pthread_detach(g_h264_read.task_thd) != 0)
	{
		ERR("pthread detached h264_read_thread failed\n");
		return -1;
	}
#endif

    SUCCESS_TRACE("start success\n");
    return 0;
}

int h264_read_stop()
{
    if(g_h264_read.init_flag == 0)
    {
        return -1;
    }

    if(g_h264_read.run_flag == 0)
    {
        return 0;
    }

    g_h264_read.run_flag = 0;
    return 0;
}

int h264_read_uninit()
{
    h264_read_stop();
    DestroyDataSequeue(g_h264_read.fram_queue);
    g_h264_read.fram_queue = NULL;
    return 0;
}

int h264_read_fram(fram_info_t *p_fram)
{
    if(NULL == p_fram)
    {
        return -1;
    }

    return DeDataQueue(g_h264_read.fram_queue, (char*)&p_fram, sizeof(fram_info_t));
}

static int GetSpsPpsSeiLen(int *spsLen, int *ppsLen, char *pspsstart, char *pppsstart,  int len, char *data)
{
        int pos = 0;
		int spsflag = 0;
		int ppsflag = 0;
        int seiLen = 0, nalType = 0;
        int pps = 0, sps = 0;
        char *ptr = data;
        while(pos < len)
		{
            if(ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x00 && ptr[3] == 0x01)
			{
                nalType = *(ptr+4);
            }
            switch(nalType)
			{
                case 0x67:
                    sps ++;
					*pspsstart = *ptr;
					pspsstart++;
                    break;

                case 0x68:
                    pps ++;
					*pppsstart = *ptr;
					pppsstart++;

                    break;

                case 0x06:
                    seiLen ++;
                    break;

				case 0x65:
				    goto __Ok;
				    break;

                default:
                    return 0;
            }

            ptr ++;
            pos ++;
        }

       __Ok:
        *spsLen = sps;
        *ppsLen = pps;
        return seiLen;
}

static void *h264_read_thread(void *arg)
{
    int *run_flag = (int *)arg;
    int n = 0; //当前读取到的数据大小
    FILE *f_h264 = NULL;
    int n_last = 0; //上一次读取的文件还有多少没有发送的
    int total_len = 0;
    
    char buf[MAXBUF] = {};
    int fram_rate = 25;
    unsigned int timestamp = 0;
    fram_info_t fram_info = { 0 };
    int getsps_flag = 0;

    int SPSlen = 0;
	int PPSlen = 0;
	char *pSPSstart = NULL;
	char *pPPSstart = NULL;
	char SPSbuf[128] = {0};
	char PPSbuf[128] = {0};
	int SEIlen = 0;
	int VPSlen = 0;
	char *pSEIstart = NULL;
	char *pVPSstart = NULL;
	char SEIbuf[128] = {0};
	char VPSbuf[128] = {0};

    while (*run_flag)
    {
        //这里循环读取h264文件发送
        f_h264 = fopen(SEND_FILE, "rb");
		if(NULL == f_h264)
		{
			printf("open file failed errno%d\n",errno);
		}

        while((n = fread(buf + n_last, 1, MAXBUF - n_last, f_h264)) > 0)
        {
            char *start_code = NULL;
            char *end_code = NULL;
            start_code = find_nal_start_code(buf, MAXBUF);
            int send_count = 0;
            n += n_last;

            if(start_code)
            {
                int send_len = 0;
                send_count = 0;
                while((end_code = find_nal_start_code(start_code + 4, n - send_len)) > 0)
                {

                    //fprintf(stdout, "send type:%d size:%ld send_count:%d\n ", *(start_code+4)&0x1f, end_code - start_code, send_count);
                    timestamp += 90000/fram_rate;
                    fram_info.timestamp = timestamp;
                    fram_info.fram_type = (*(start_code+4)&0x1f) == 7? FRAME_TYPE_I: FRAME_TYPE_P;
                    fram_info.fram_size = end_code - start_code;
                    fram_info.fram_buff = (char *)malloc(fram_info.fram_size);
                    memset(fram_info.fram_buff, 0, fram_info.fram_size);
                    memcpy(fram_info.fram_buff, start_code, fram_info.fram_size);
                    EnDataQueue_Loop(g_h264_read.fram_queue, (char*)&fram_info, sizeof(fram_info));
                    g_h264_read.fram_count++;
                    send_len += end_code - start_code;
                    total_len += end_code - start_code;
                    start_code = end_code;
                    send_count++;

                    if(fram_info.fram_type == FRAME_TYPE_I && getsps_flag == 0)
                    {
                        //GetSpsPpsSeiLen(&SPSlen, &PPSlen, SPSbuf, PPSbuf, n - send_len, start_code);
                        getsps_flag = 1;
                        //gstmainvideocodeiflame(SPSbuf, PPSbuf, SEIbuf, VPSbuf, SPSlen, PPSlen, SEIlen, VPSlen);
                    }

					usleep(1000 * 20);
                }

                if(send_count > 0 && n == MAXBUF)
                {

                    n_last = n - (start_code - buf);
                    memmove(buf, start_code, n_last);
                }
                else
                {

                        total_len += n - send_len;
                        //fprintf(stdout, "send type:%d size:%d receive_count:%d\n ", *(start_code+4)&0x1f, n, send_count);
                        timestamp += 90000/fram_rate;
                        fram_info.timestamp = timestamp;
                        fram_info.fram_type = (*(start_code+4)&0x1f) == 7? FRAME_TYPE_I: FRAME_TYPE_P;
                        fram_info.fram_size = n - send_len;
                        fram_info.fram_buff = (char *)malloc(fram_info.fram_size);
                        memset(fram_info.fram_buff, 0, fram_info.fram_size);
                        memcpy(fram_info.fram_buff, start_code, fram_info.fram_size);
                        EnDataQueue_Loop(g_h264_read.fram_queue, (char*)&fram_info, sizeof(fram_info));
                        g_h264_read.fram_count++;
                        n_last = 0;
            	}     
			}  
        }

        printf("send total_len:%d n:%d\n", total_len, n);
        
        fclose(f_h264);
        usleep(1000);
        //break;
    }
    return ;
}


static void *h264_write_thread(void *arg)
{
    int *run_flag = (int *)arg;
    FILE *f_h264 = NULL;

    //这里循环读取h264文件发送
    f_h264 = fopen(WRITE_FILE, "wb+");
    if(NULL == f_h264)
    {
        printf("open file failed errno%d\n",errno);
    }
    while (*run_flag)
    {
        
        fram_info_t fram_info = { 0 };
        if(DeDataQueue(g_h264_read.fram_queue, (char*)&fram_info, sizeof(fram_info)) != 0)
        {
            usleep(1000);
            continue ;
        }

        fwrite(fram_info.fram_buff, 1, fram_info.fram_size, f_h264);
        free(fram_info.fram_buff);
    }
    SUCCESS_TRACE("quit success\n");
    fclose(f_h264);
    return;
}