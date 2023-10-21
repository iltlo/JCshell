CC=gcc
EXE=main ./utility/tloop ./utility/segfault ./utility/forever

all: $(EXE)

main: main.c
	$(CC) $< -o $@

clean:
	rm $(EXE) *.o

.PRECIOUS: %.o