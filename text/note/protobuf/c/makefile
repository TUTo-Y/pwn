FLAGS = -fno-stack-protector -no-pie
 
demo:demo.c demo.pb-c.c
	gcc $(FLAGS) -o demo demo.c demo.pb-c.c -lprotobuf-c `pkg-config --cflags --libs protobuf`