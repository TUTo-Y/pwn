#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ctf.pb-c.h"
char content[0x200];

void backdoor()
{
    execve("/bin/sh", NULL, NULL);
}
void init()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main()
{
    char buf[0x10];
    init();

    printf("demo:");
    int size = read(0, content, sizeof(content));

    Demo__DemoMs *demo_message = demo__demo_ms__unpack(NULL, size, (const uint8_t *)content);

    printf("demo_size: %d\n", demo_message->demo_size);
    printf("demo_content: %s\n", demo_message->demo_content.data);
    
    memcpy(buf, demo_message->demo_content.data, demo_message->demo_size);

    return 0;
}