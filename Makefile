CC = gcc
CFLAGS = -O0 -ggdb3
LDFLAGS = -ljansson

all: nvbiosdump

nvbiosdump: nvbiosdump.c nvbios.h
	$(CC) $(CFLAGS) nvbiosdump.c $(LDFLAGS) -o nvbiosdump

clean:
	rm -vf nvbiosdump