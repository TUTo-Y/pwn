SOURCE = demo.c
TARGET = demo
PROTO_SRC = $(wildcard *.proto)
PROTO_C = $(patsubst %.proto,%.pb-c.c,$(PROTO_SRC))
PROTO_H = $(patsubst %.proto,%.pb-c.h,$(PROTO_SRC))

CFLAGS = -fno-stack-protector -no-pie -s
LDFLAGS = -lprotobuf-c

$(TARGET): $(SOURCE) $(PROTO_C)
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.pb-c.c: %.proto
	protoc --c_out=. $<

clean:
	rm -f $(TARGET) $(PROTO_C) $(PROTO_H)