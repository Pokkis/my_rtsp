#include <unistd.h>
#include <fcntl.h>
#include "rtsptask.h"


int main()
{
	startRtspServer(554, 0, 0, 1400, 2);
	while (1)
	{
		sleep(1);
	}
	return 0;
}