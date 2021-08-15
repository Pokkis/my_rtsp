#ifndef _H264READ_H_
#define _H264READ_H_
#ifdef __cplusplus
extern "C"
{
#endif
typedef enum _FRAM_TYPE_E
{
    FRAME_TYPE_I = 0x0a,
    FRAME_TYPE_P = 0x0b,
}FRAM_TYPE_E;

typedef struct _fram_info_t
{
    int fram_type;
    unsigned int timestamp;
	unsigned int framnum;
    unsigned int fram_size;
    char *fram_buff;
}fram_info_t;


int h264_read_init();
int h264_read_start();
int h264_read_stop();
int h264_read_uninit();
int h264_read_fram(fram_info_t *p_fram);

#ifdef __cplusplus
}
#endif
#endif