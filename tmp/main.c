#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <time.h>
#include <unistd.h>

int main()
{
    char str[10] = { 0 };
    int a, b;

    printf("v1 = %u v2 = %u", -1, -101);
    scanf("%s", str);
    a = atoi(str);
    scanf("%s", str);
    b = atoi(str);

    printf("%d %d %d\n", a, b, a-b);

    return 0;
}
