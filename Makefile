CC=gcc
EXE=main

main: main.o
	$(CC) $< -o $@

clean:
	rm $(EXE) *.o

.PRECIOUS: %.o