CC = gcc
FLAGS = -Wall -g

build: resolver

resolver: resolver.o
	$(CC) $(FLAGS) $< -o $@

resolver.o: resolver.cpp resolver.hpp
	$(CC) $(FLAGS) -c $< -o $@

run: build
	./resolver

.PHONY: build clean run

clean:
	rm -f resolver.o resolver message.log dns.log