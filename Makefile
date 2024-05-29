CC = gcc
CFLAGS = -g -std=c11 -Wpedantic -Wall -Wextra -Werror -Wvla 
MEMCHECK=valgrind --tool=memcheck --leak-check=full --track-origins=yes

all: clean
	$(CC) $(CFLAGS) -o main main.c cache.c 

memcheck: all
	$(MEMCHECK) ./main

clean:
	rm -f ./main