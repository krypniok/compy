# Compy: Ein Bare-Metal C -> ELF Compiler

## Übersicht
Ein minimalistischer Compiler, der C-Code direkt in eine **ausführbare ELF-Binärdatei** (x86 32-bit) übersetzt.
Keine externen Bibliotheken (kein `regex.h`, kein `libelf`), kein Assembler-Zwischenschritt. Ideal für Bootstrapping in Hobby-OS Umgebungen.

## Funktionsweise
1. **Parsing**: Liest Zeilen via `sscanf` (Quick & Dirty).
2. **Code Gen**: Schreibt rohe x86 Opcodes (Machine Code) in einen Buffer.
3. **Linking**: Erstellt manuell einen ELF-Header und schreibt alles in eine Datei.

## Features
- [x] ELF Header Generierung (manuell)
- [x] Variablen auf dem Stack (`[ebp-x]`)
- [x] Addition und Zuweisung
- [x] Einfache Zuweisung (`var = val`)
- [x] Pointer: `int *p`, `p = &a`, `*p = val`, `var = *p`
- [x] Arrays: `int arr[N]`, `arr[i] = val`, `var = arr[i]` (Konstanter Index)
- [x] Return Value (via `exit` Syscall, da keine C-Runtime)
- [x] Control Flow: `if (==, !=) ... { ... } else { ... }` (inkl. Nested)
- [x] Control Flow: `if ( ... &&/|| ... )` (Logische Verknüpfungen)
- [x] Control Flow: `while (var < val) { ... }`
- [x] Control Flow: `for (init; cond; inc) { ... }`
- [x] Control Flow: `switch (var) { case x: ... break; default: ... }`
- [x] Control Flow: `break` in Schleifen
- [x] Control Flow: `continue` in Schleifen
- [x] Functions: Definition und Aufruf (`void func()`, `func()`)
- [x] Expressions: `return a + b;`
- [x] Output: `print(var)` (itoa + write syscall)
- [x] Output: `print("string")` (Inline Data + write syscall)
- [x] Kommentare: `// ...`
- [x] **Structs**: `typedef struct`, Member-Zugriff (`.`), Pointer-Zugriff (`->`)
- [x] **Typen**: `int`, `char`, `uint32_t`, `uint8_t`
- [x] **Bitwise**: `&`, `|`, `^`, `<<`, `>>`
- [x] **Inkrement/Dekrement**: `i++`, `i--`
- [x] **Sizeof**: `sizeof(int)`, `sizeof(struct)`
- [x] **Dynamischer Speicher**: `sys_malloc`, `sys_free` (via `brk` Syscall)
- [x] **Datei I/O**: `fopen`, `fgetc`, `fclose`, `sys_write`
- [x] **String Lib**: `sys_strlen`, `sys_strcpy`, `sys_strcmp`, etc.
- [x] **Self-Hosting**: Der Compiler kann seinen eigenen Quellcode kompilieren!

## Verwendung
```bash
# 1. Host-Compiler bauen (mit GCC)
gcc -o compiler compiler.c

# 2. Beispiel kompilieren
./compiler example.c example
./example
```
