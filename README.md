Overview

This project simulates cache and runs a RISC-V simulator program. The program identifies which accesses would cause a cache hit and which accesses would cause a cache miss when an assembly program is executing.

Files

Makefile: Automates the build and clean processes.
simulator.c: The main C file that contains the code for simulating RISC-V simulator code and also cache simulation.
simulator.o: The object file of above .c file
input.s: Input file containing the RISC-V assembly code.
input.output: This output file contains cache simulation data of the respective input.s
myFile.txt: This contains the dump output of the cache


Commands

Since I am using mingw gcc compiler on vscode the commands to run is
mingw32-make
./riscv_sim
For ubuntu the comands are
make
./riscv_sim

Note: Make sure every file is in the same directory.

Limitations :

Our code handles different types of errors and has limitations too.

LIMITATIONS

1. Our code is very sensitive to the syntax so the syntax needs to be correct . For example lui instruction needs to have a decimal immediate and all immediates should be in decimal form only(taken from assembler).

2. In the input file all the lines must start from the first character itself. If the first character is “ ” then the parsing fails. The same thing happens if there is an empty line.

3. If an incorrect breakpoint is given then it is not handled correctly.

4. The limitations for values of .dword,.word,.byte,.half have not been applied.

5. The input.output file needs to be empties everytime.

We have used the below test cases

1. 
    Input.s                                                  config.txt
    .data                                                    256
    .dword 10, 20, 30, 40, 50                                16
    .text                                                    1
    lui x3, 0x10                                             LRU
    ld x4, 0(x3)                                             WB
    ld x4, 8(x3)
    ld x4, 16(x3)
    ld x4, 24(x3)
    ld x4, 32(x3)

2. 
    Input.s                                                  config.txt
    .data                                                    1024
    .dword 20, 30, 40, 50, 60                                16
    .text                                                    1
    lui x3, 0x10                                             FIFO
    sd x4, 0(x3)                                             WT
    ld x4, 8(x3)
    ld x4, 0(x3)
    ld x4, 16(x3)
    ld x4, 24(x3)
