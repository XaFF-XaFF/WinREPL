# WinREPL
WinREPL is a "read-eval-print loop" shell on Windows that is useful for testing/learning x86 and x64 assembly.

![WinREPL](/screenshot.png?raw=true "WinREPL")

### Methodology
WinREPL is a debugger (parent process) that hollows out a copy of itself (child process).

1. Parent process retrieves input from the user
2. Machine code is generated with the ASMTK library
3. Resulting bytes are written to a child process thread context
4. Child process thread is resumed
5. Parent process polls for debug events

### Commands
Multiple assembly mnemonics can be executed on a single line by separating with semi-colons. Refer to ASMTK documentation for  other syntactic sugar.

Besides being a raw assembler, there are a few extra commands.

```
.help                   Show this help screen.
.registers              Show more detailed register info.
.read addr size         Read from a memory address.
.write addr hexdata     Write to a memory address.
.allocate size          Allocate a memory buffer.
.loadlibrary path       Load a DLL into the process.
.kernel32 func          Get address of a kernel32 export.
.shellcode hexdata      Execute raw shellcode.
.peb                    Loads PEB into accumulator.
.reset                  Start a new environment.
.quit                   Exit the program.
```

The following commands are not yet implemented but on the Todo list:

```
.dep addr size [0/1]    Enable or disable NX-bit.
.stack                  Dump current stack memory contents.
.string data            Push a string onto the stack.
.errno                  Get last error code in child process.
```

### License
ZLIB 
Original [repository](https://github.com/zerosum0x0/WinREPL/)