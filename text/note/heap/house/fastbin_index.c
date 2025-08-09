// 通过fastbin_index函数计算fast bin的索引
// gcc fastbin_index.c -o fastbin_index
#define DEMO
#include <demo.h>

#define SIZE_SZ sizeof(size_t)
#define fastbin_index(sz) \
	((((unsigned int)(sz)) >> 4) - 2)

int main()
{
	printf("%x\n", fastbin_index(0x78));

	assert(fastbin_index(0x78) == 5);

	
	return 0;
}