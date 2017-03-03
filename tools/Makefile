default: makekeys
all: default

ecc.o: ../src/hal/sec/nanoecc/ecc.c ../src/hal/sec/nanoecc/ecc.h
	gcc -g -o ecc.o -c ../src/hal/sec/nanoecc/ecc.c

makekeys.o: makekeys.c ../src/hal/sec/nanoecc/ecc.h
	gcc -I.. -g -o makekeys.o -c makekeys.c

makekeys: ecc.o makekeys.o
	gcc -o makekeys makekeys.o ecc.o

clean:
	rm -f ecc.o makekeys.o makekeys

.PHONY: default all clean