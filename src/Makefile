CC=gcc
CFLAGS=-g -Wall -DUSE_MEM_POOL
LIBRARY=-lpthread

objs = sha1.o base64.o mem.o log.o sock.o sha1_test.o log_test.o mem_test.o sock_test.o wsock.o ws_parse.o wsock_test.o ws_echo.o

all:common test

common:$(objs)

$(objs): %.o: %.c
	$(CC) -c $(CFLAGS)  $< -o $@ $(LIBRARY)

test:mem_test log_test sock_test sha1_test app_test

sha1_test:$(objs)
	$(CC) -g -o sha1_test sha1_test.o sha1.o base64.o $(LIBRARY)

mem_test:$(objs)
	$(CC) -g -o mem_test mem_test.o log.o mem.o  $(LIBRARY)

log_test:$(objs)
	$(CC) -g -o log_test log_test.o log.o $(LIBRARY)

sock_test:$(objs) 
	$(CC) -g -o sock_test sock_test.o mem.o log.o sock.o $(LIBRARY)

wsock_test:$(objs)
	$(CC) -g -o wsock_test wsock_test.o mem.o log.o sock.o wsock.o ws_parse.o sha1.o base64.o $(LIBRARY)

app_test:$(objs)
	$(CC) -g -o app_test ws_echo.o mem.o log.o sock.o wsock.o ws_parse.o sha1.o base64.o $(LIBRARY)

.PHONY: clean
clean:
	rm -rf *.o *_test

