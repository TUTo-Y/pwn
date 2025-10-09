all: pwn64 pwn32 makefile

pwn64: pwn.c sandbox64.h
	gcc -g -DD64 -o pwn64 pwn.c

pwn32: pwn.c sandbox32.h
	gcc -g -DD32 -m32 -o pwn32 pwn.c

sandbox64.h:sandbox.asm
	seccomp-tools asm ./sandbox.asm -a amd64 -f c_source > sandbox64.h

sandbox32.h:sandbox.asm
	seccomp-tools asm ./sandbox.asm -a i386 -f c_source > sandbox32.h

clean:
	rm -f pwn64 pwn32 sandbox32.h sandbox64.h