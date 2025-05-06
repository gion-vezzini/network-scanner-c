CC = gcc
CFLAGS = -Wall -pthread

all: scanner

scanner: src/main.o src/scanner.o
	$(CC) $(CFLAGS) -o scanner src/main.o src/scanner.o

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o scanner
