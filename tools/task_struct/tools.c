#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(int argc, char *argv[])
{
    char buf[0x100] = {0};
    if(argc != 3)
    {
        printf("Usage: %s <path>\n", argv[0]);
        return 1;
    }
    int fd = open("/dev/tuc", O_RDWR);
    if(fd < 0)
    {
        perror("open");
        return 1;
    }
    
    printf("ID: %s\n", argv[1]);
    printf("设置: %s\n", argv[2]);
    ioctl(fd, atoi(argv[2]), atol(argv[1]));
    
    read(fd, buf, 0x100);
    printf("%s\n", buf);

    close(fd);

    return 0;
}