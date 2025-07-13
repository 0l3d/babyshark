CC = gcc
CFLAGS = -g -O2 -march=native
LDFLAGS = -lpcap
TARGET = babyshark
SOURCES = babyshark.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
