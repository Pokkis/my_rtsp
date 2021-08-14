#include <unistd.h>
#include <fcntl.h>
#include "rtsptask.h"
#include "h264read.h"

int main()
{
	h264_read_init();
	startRtspServer(554, 0, 1, 1400, 2);
	while (1)
	{
		h264_read_start();
		sleep(1);
	}

	return 0;
}