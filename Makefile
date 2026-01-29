CC = gcc
CFLAGS = -Wall -g

all: compiler example

compiler: compiler.c
	$(CC) $(CFLAGS) -o compiler compiler.c

example: compiler example.c
	./compiler example.c example
	chmod +x example

clean:
	rm -f compiler example

run: example
	./example