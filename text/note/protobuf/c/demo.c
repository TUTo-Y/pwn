#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "demo.pb-c.h"


void backdoor()
{
    execve("/bin/sh", NULL, NULL);
}

void success(DemoPack__DemoMsg *msg)
{
    char buf[0x10];
    memcpy(buf, msg->str.data, msg->size);
}


int main()
{
    char *s = NULL;
    DemoPack__DemoMsg *msg = NULL;
    
    // 读取msg字符串
    size_t s_len = 0;
    scanf("%ld", &s_len);
    s = (char *)malloc(s_len);
    read(0, s, s_len);

    // 反序列化
    if(msg = demo_pack__demo_msg__unpack(NULL, s_len, s))
    {
        printf("successfully.\n");
        success(msg);
    }
    else
    {
        printf("Failed\n");
    }

    return 0;
}