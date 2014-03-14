nasm -f elf64 -o fork_stub-x64.o fork_stub-x64.asm; ld -o fork_stub-x64 fork_stub-x64.o
for i in $(objdump -d fork_stub-x64 |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo
