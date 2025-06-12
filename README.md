RISC-V Simulator with Cache Simulation
======================================

This project is a RISC-V 64-bit assembly simulator that includes execution support, breakpoints, memory and register dumps, and cache simulation for hits and misses.

------------------------------------------------------------
FILES
------------------------------------------------------------

1. Makefile          : Automates the build and clean process.
2. simulator.c       : Main C file with RISC-V and cache simulation logic.
3. simulator.o       : Object file generated during compilation.
4. input.s           : Sample RISC-V assembly program.
5. input.output      : Output showing cache hit/miss data.
6. myFile.txt        : Cache memory dump output.
7. config.txt        : Cache configuration file.

------------------------------------------------------------
COMMANDS
------------------------------------------------------------

For Windows (using MinGW + VSCode):
    mingw32-make
    ./riscv_sim

For Ubuntu/Linux:
    make
    ./riscv_sim

Note: Ensure all files are in the same directory before building or running.

------------------------------------------------------------
SIMULATOR SHELL COMMANDS
------------------------------------------------------------

load <filename>            Load and initialize a RISC-V program.
run                        Run the loaded program until halt or breakpoint.
regs                       Print all 64-bit register values.
step                       Execute the next instruction.
mem <addr> <count>         Show <count> memory values from <addr>.
break <line>               Set a breakpoint at the given line number.
del break <line>           Delete breakpoint from the given line.
show-stack                 Show function call stack.
exit                       Exit the simulator.

------------------------------------------------------------
CACHE SIMULATION COMMANDS
------------------------------------------------------------

cache_sim enable <config>  Enable cache simulation with config file.
cache_sim disable          Disable cache simulation.
cache_sim status           Display cache settings.
cache_sim invalidate       Invalidate all cache lines.
cache_sim dump <file>      Dump current cache contents to file.
cache_sim stats            Show cache hit/miss stats.

------------------------------------------------------------
CACHE CONFIG FORMAT (config.txt)
------------------------------------------------------------

<cache size in bytes>
<block size in bytes>
<associativity>       (1=DM, 0=FA, 2/4/8=SA)
<replacement policy>  (FIFO, LRU, RANDOM)
<write policy>        (WT, WB)

Example:
256
16
1
LRU
WB

------------------------------------------------------------
KNOWN LIMITATIONS
------------------------------------------------------------

1. Syntax-sensitive:
   - Immediates must be decimal.
   - No leading spaces at the start of a line.
   - No empty lines allowed.

2. Breakpoint validation not fully robust.

3. Memory allocations fail if .dword/.word/.byte/.half appear in multiple lines or exceed 50 entries.

4. Value range checks for memory types not enforced.

5. input.output file must be emptied before running again.

------------------------------------------------------------
TEST CASES
------------------------------------------------------------

Basic Instructions:
-------------------
addi x5, x5, 0
lui x4, 16
addi x5, x5, -1
sd x5, 2(x4)
addi x5, x5, 1

Function and Stack:
-------------------
main: addi x10, x0, 2
lui sp, 80
jal x1, fact
beq x0, x0, exit
fact: addi sp, sp, -16
sd x1, 8(sp)
sd x10, 0(sp)
addi x5, x10, -1
blt x0, x5, L1
addi x10, x0, 1
addi sp, sp, 16
jalr x0, 0(x1)
L1: addi x10, x10, -1
jal x1, fact
addi x6, x10, 0
ld x10, 0(sp)
ld x1, 8(sp)
addi sp, sp, 16
addi x20, x0, 0
addi x8, x0, 0
mul: add x8, x8, x6
addi x20, x20, 1
bne x20, x10, mul
add x10, x8, x0
jalr x0, 0(x1)
exit: add x0, x0, x0

Loop and Arithmetic:
--------------------
add x8, x8, x6
addi x20, x20, 1
bne x20, x10, mul
add x10, x8, x0

------------------------------------------------------------
CACHE TEST CASES
------------------------------------------------------------

Test Case 1:
------------
input.s
-------
.data
.dword 10, 20, 30, 40, 50
.text
lui x3, 0x10
ld x4, 0(x3)
ld x4, 8(x3)
ld x4, 16(x3)
ld x4, 24(x3)
ld x4, 32(x3)

config.txt
----------
256
16
1
LRU
WB

Test Case 2:
------------
input.s
-------
.data
.dword 20, 30, 40, 50, 60
.text
lui x3, 0x10
sd x4, 0(x3)
ld x4, 8(x3)
ld x4, 0(x3)
ld x4, 16(x3)
ld x4, 24(x3)

config.txt
----------
1024
16
1
FIFO
WT

------------------------------------------------------------
OUTPUT FORMAT
------------------------------------------------------------

During Execution:
-----------------
Executed instruction add x8, x9, x5; PC=0x00001000

Cache Simulation (input.output):
--------------------------------
R: Address: 0x20202, Set: 0x02, Miss, Tag: 0x202, Clean
W: Address: 0x10306, Set: 0x06, Hit, Tag: 0x103, Dirty

------------------------------------------------------------
AUTHOR & CREDITS
------------------------------------------------------------

Developed as part of Lab 7 RISC-V + Cache Simulator assignment.
