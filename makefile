all: riscv_sim

riscv_sim: simulator.o
	gcc -Wall -g -o riscv_sim simulator.o

simulator.o: simulator.c
	gcc -Wall -g -c simulator.c

run: riscv_sim
	./riscv_sim input.s
	
clean:
	rm -f simulator.o riscv_sim

.PHONY: all clean run
