CC = gcc
CPP = g++
AR = ar
TARGET = rtsp

SOURCES = $(wildcard *.cpp)  $(wildcard *.c)
OBJS = $(patsubst %.cpp,%.o, $(SOURCES)) $(patsubst %.c,%.o, $(SOURCES))

INCLUDE = 	-I./
#CFLAGS = -Wall -Os
CFLAGS = -Wall -g
CFLAGS += $(INCLUDE)

all : $(TARGET)

$(TARGET) : $(SOURCES) 
	$(CC)  $(CFLAGS) $^ -o $(TARGET) 

	
.PHONY = clean
	
clean : 
	rm -rf *.o $(TARGET)
