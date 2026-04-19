CC      = gcc
TARGET  = sysinfo_api
SRC     = sysinfo_api.c

CFLAGS  = -Wall -Wextra -O2
LIBS    = -lmicrohttpd -ljansson

.PHONY: all clean install-deps

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)
