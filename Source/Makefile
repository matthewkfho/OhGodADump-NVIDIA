CC=gcc
 
CFLAGS = -g -march=native
CPPFLAGS = -std=gnu99
 
LDFLAGS=-O2
 
# require libjansson-dev package
LDLIBS = -ljansson
 
SOURCES = nvbiosdump.c
OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=nvbiosdump
 
 
CODEDIR1=jansson
 
.PHONY: depcode1
 
all: depcode1 $(SOURCES) $(OUTPUT)
 
#depcode1:
#       $(MAKE) -C $(CODEDIR1)
 
 
$(SOURCES): nvbios.h
 
$(OUTPUT): $(OBJECTS)
        $(CC) $(OBJECTS) $(LDLIBS) $(LDFLAGS) -o $@
 
.cpp.o:
        $(CC) $(CFLAGS) $(CPPFLAGS) -c $<
 
.c.o:
        $(CC) $(CFLAGS) -c $<
 
clean:
        rm -f *.o $(OUTPUT)
 
install: clean all
        strip -s $(OUTPUT)
 
 
