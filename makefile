attack: attack.o
	./attack.o

attack.o: src/attack.c clean
	gcc -Wall -o attack.o src/*.c

clean:
	rm -f attack.o