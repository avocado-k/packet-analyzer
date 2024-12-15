CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap

SRCS = src/main.c src/capture.c src/packet.c
OBJS = $(SRCS:.c=.o)
TARGET = packet_analyzer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)