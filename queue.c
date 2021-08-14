#include "queue.h"
#include <string.h>
#include <stdlib.h>

sequeue_data_t *CreateEmptyDataSequeue(int maxDataCount, int oneDataSize)
{
    sequeue_data_t *queue;
    queue = (sequeue_data_t *)malloc(sizeof(sequeue_data_t));

    if (queue == NULL)
        return NULL;

    queue->data = (char *)malloc(oneDataSize * maxDataCount);
    if (NULL == queue->data)
    {
        free(queue);
        return NULL;
    }
        

    queue->front = 0;
    queue->rear = 0;
    queue->maxQueueSize = maxDataCount;
    printf("[%s:%d]####front=%d,rear=%d,max_queue_size:%d####\n", __FILE__, __LINE__, queue->front, queue->rear, queue->maxQueueSize);
    pthread_mutex_init(&queue->EnQueueLock, NULL);
    pthread_mutex_init(&queue->DeQueueLock, NULL);
    return queue;
}

void DestroyDataSequeue(sequeue_data_t *queue)
{
    if (queue == NULL)
    {
        ERR("queue=%p\n", queue);
        return;
    }

    if (queue->data)
    {
        free(queue->data);
        queue->data = NULL;
    }

    free(queue);
    queue = NULL;
}

int EmptyDataSequeue(sequeue_data_t *queue)
{
    if (NULL == queue || queue->data == NULL)
        return -1;
    //printf("[%s:%d]####queue=%p,front=%d,rear=%d####\n",__FILE__,__LINE__,queue,queue->front,queue->rear);
    return (GetSequeueSize(queue) == 0 ? 1 : 0);
}

int FullDataSequeue(sequeue_data_t *queue)
{
    if (NULL == queue || queue->data == NULL)
        return -1;

    return (GetSequeueSize(queue) == queue->maxQueueSize? 1 : 0);
}

int EnDataQueue(sequeue_data_t *queue, char *inData, int oneDataSize)
{
    pthread_mutex_lock(&queue->EnQueueLock);
    if (NULL == queue || queue->data == NULL)
    {
        pthread_mutex_unlock(&queue->EnQueueLock);
        return -1;
    }

    if (1 == FullDataSequeue(queue))
    {
        pthread_mutex_unlock(&queue->EnQueueLock);
        return -1; /* full */
    }

    unsigned int position = queue->rear % queue->maxQueueSize;
    memset(queue->data + position * oneDataSize, 0, oneDataSize);
    memcpy(queue->data + position * oneDataSize, inData, oneDataSize);
    queue->rear++;

    pthread_mutex_unlock(&queue->EnQueueLock);
    return 0;
}

int DeDataQueue(sequeue_data_t *queue, char *outData, int oneDataSize)
{
    pthread_mutex_lock(&queue->DeQueueLock);
    if (NULL == queue || queue->data == NULL)
    {
        pthread_mutex_unlock(&queue->DeQueueLock);
        return -1;
    }

    if (1 == EmptyDataSequeue(queue))
    {
        pthread_mutex_unlock(&queue->DeQueueLock);
        return -1; /* empty */
    }

    unsigned int position = queue->front % queue->maxQueueSize;
    if (NULL != outData)
    {
        memcpy(outData, queue->data +  position * oneDataSize, oneDataSize);
    }
    queue->front++;

    pthread_mutex_unlock(&queue->DeQueueLock);

    return 0;
}

unsigned int GetSequeueSize(sequeue_data_t *queue)
{
    if (NULL == queue || queue->data == NULL)
        return -1;

    unsigned int queuesize = 0;
    queuesize = (queue->rear >= queue->front) ? queue->rear - queue->front : queue->rear - queue->front;
    return queuesize;
}

int DeAllDataQueue(sequeue_data_t *queue)
{
    if (NULL == queue || queue->data == NULL)
        return -1;

    pthread_mutex_lock(&queue->EnQueueLock);
    queue->front = 0;
    queue->rear = 0;
    pthread_mutex_unlock(&queue->EnQueueLock);
    return 0;
}

int EnDataQueue_Loop(sequeue_data_t *queue, char *inData, int oneDataSize)
{
    int ret = -1;
    if(EnDataQueue(queue, inData, oneDataSize) != 0)
    {
        char *tmp = (char *)malloc(oneDataSize);
        if(tmp)
        {
            DeDataQueue(queue, tmp, oneDataSize);
            ret = EnDataQueue(queue, inData, oneDataSize);
            free(tmp);
        }
        
    }

    return ret;
}