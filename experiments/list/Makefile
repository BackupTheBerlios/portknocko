CFLAGS=-g -Wall
TARGETS=match
LDLIBS=-lpthread

all: $(TARGETS)

match: main.o list.o parse_port.o
	$(CC) -o $(LDFLAGS) $@ $^ $(LDLIBS)

test: match
	./match 5000	

clean:
	rm -fv *.o *~ $(TARGETS) core*
