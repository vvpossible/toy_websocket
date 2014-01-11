CC=gcc
CFLAGS=-g -Wall -DUSE_MEM_POOL
LIBRARY=-lpthread


objs = sha1.o base64.o mem.o log.o sock.o \
       sha1_test.o log_test.o mem_test.o  \
       sock_test.o wsock.o ws_parse.o \
       wsock_test.o ws_echo.o


$(objs): %.o: %.c
	$(CC) -c $(CFLAGS)  $< -o $@ $(LIBRARY)


all: mem_test log_test sock_test sha1_test app_test

sha1_test_obj = sha1_test.o sha1.o base64.o
sha1_test:$(sha1_test_obj)
	$(CC) -g -o sha1_test $(sha1_test_obj) $(LIBRARY)

mem_test_objs = mem_test.o log.o mem.o
mem_test:$(mem_test_objs)
	$(CC) -g -o mem_test $(mem_test_objs)  $(LIBRARY)

log_test_objs = log_test.o log.o
log_test:$(log_test_objs)
	$(CC) -g -o log_test $(log_test_objs) $(LIBRARY)

sock_test_objs = sock_test.o mem.o log.o sock.o
sock_test:$(sock_test_objs) 
	$(CC) -g -o sock_test $(sock_test_objs) $(LIBRARY)

wsock_test_objs = wsock_test.o mem.o log.o sock.o wsock.o ws_parse.o sha1.o base64.o
wsock_test:$(wsock_test_objs)
	$(CC) -g -o wsock_test $(wsock_test_objs) $(LIBRARY)

app_test_objs = ws_echo.o mem.o log.o sock.o wsock.o ws_parse.o sha1.o base64.o
app_test:$(app_test_objs)
	$(CC) -g -o app_test $(app_test_objs) $(LIBRARY)

.PHONY: clean
clean:
	rm -rf *.o *_test *.d


sources = sha1.c base64.c mem.c log.c sock.c \
          sha1_test.c log_test.c mem_test.c \
          sock_test.c wsock.c ws_parse.c \
          wsock_test.c ws_echo.c

include $(sources:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
        $(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
        sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
        rm -f $@.$$$$


