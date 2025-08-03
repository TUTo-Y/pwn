FLAGS = -fno-stack-protector -no-pie
 
demo:demo.cc demo.pb.cc
	g++ $(FLAGS) -o demo demo.cc demo.pb.cc `pkg-config --cflags --libs protobuf`
	
