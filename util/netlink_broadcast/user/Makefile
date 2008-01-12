CC=gcc
TARGET=user
OBJS=user.o
CFLAGS=-I /usr/src/linux-$(shell uname -r)/include

all : $(TARGET)

$(TARGET):  $(OBJS)
	$(CC) -o $(TARGET) $(OBJS)

clean:
	rm -f $(TARGET) *.o core*
