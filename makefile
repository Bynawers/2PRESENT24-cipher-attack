main: main.o
	./main.o

main.o: src/main.c clean
	gcc -Wall -o main.o src/*.c

clean:
	rm -f main.o