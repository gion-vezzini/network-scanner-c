SRCS = src/main.c src/scanner.c

TARGET = scanner
CFLAGS = -Wall -pthread
LDFLAGS = -pthread

ifeq ($(OS),Windows_NT)
    TARGET = scanner.exe
    LDFLAGS = -lws2_32 -pthread --static -m64
    CFLAGS =
endif

all: $(TARGET)

$(TARGET): $(SRCS)
	gcc $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean