CC=gcc

all: g_shell

g_shell: gShellReadline.c 
	gcc gShellReadline.c -o g_shell  -L/usr/local/lib -I/usr/local/include -lreadline

clean:
	rm g_shell
