SOURCE = $(wildcard *.c)
TARGET = ${SOURCE:.c=}
CC = gcc
CFLAGS = -g -o0

all:$(TARGET)

$(TARGET): %: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)