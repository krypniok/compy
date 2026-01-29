#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

// Helper macros for GCC compatibility (Compy ignores lines starting with #)
// Compy treats 'print' as a keyword. GCC needs a definition.
void print_int(int x) { printf("%d\n", x); }
void print_str(const char *x) { printf("%s", x); }
// C11 Generic selection to map print(x) to correct function
#define print(x) _Generic((x), int: print_int, char*: print_str, const char*: print_str)(x)

// --- ELF Header Definitionen (Manuell, um dependencies zu vermeiden) ---
// Wir bauen ein 32-Bit ELF Executable (i386)
typedef struct __attribute__((packed)) {
    uint8_t e_ident[16];
    uint16_t e_type;      // 2 = Executable
    uint16_t e_machine;   // 3 = i386
    uint32_t e_version;
    uint32_t e_entry;     // Entry Point Adresse
    uint32_t e_phoff;     // Program Header Offset
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct __attribute__((packed)) {
    uint32_t p_type;      // 1 = LOAD
    uint32_t p_offset;
    uint32_t p_vaddr;     // Virtuelle Adresse im Speicher
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;     // 5 = R+X, 7 = R+W+X
    uint32_t p_align;
} Elf32_Phdr;

// --- Code Buffer & State ---
char code[128 * 1024]; // 128KB Code Buffer (Changed to char for bootstrapping)
int code_pos = 0;

// --- Symbol Table ---
typedef struct {
    char name[32];
    int stack_offset; // Offset relativ zu EBP (negativ)
    int type; // 0 = int, 1 = char/byte
} Symbol;

Symbol *symbols;
int symbol_count = 0;
int current_stack = 0;
int current_param_offset = 8;

// --- Function Table ---
typedef struct {
    char name[32];
    int address;    // Adresse im Code-Buffer (-1 wenn noch unbekannt)
    int patch_head; // Liste der Call-Sites, die gepatcht werden müssen
} Function;

Function *functions;
int function_count = 0;

// --- Global Variables ---
typedef struct {
    char name[32];
    int address;
    int type; // 0 = int, 1 = char/byte
} Global;
Global *globals;
int global_count = 0;
int global_mem_offset = 0;

// --- Struct Table ---
typedef struct {
    char name[32];
    int offset;
    int type; // 0=int, 1=char
} StructMember;

typedef struct {
    char name[32];
    int size;
    StructMember members[20];
    int member_count;
} StructDef;

StructDef structs[10];
int struct_count = 0;
int current_struct_def = -1;

// Global State
int is_inside_main = 0;
int is_inside_func = 0; // 1 = in function, 0 = global scope
uint32_t main_addr = -1; // Startadresse von main() (Init mit -1)
int is_parsing_struct = 0;
int g_debuglevel = 0;
int current_line = 0;

// --- Dynamic Memory (Malloc/Free) ---
int heap_start = 0;
int heap_top = 0;

#ifndef __COMPY__
void* sys_malloc(int size) { return malloc(size); }
void sys_free(void* ptr) { free(ptr); }
#else
int sys_malloc(int size) {
    if (heap_start == 0) {
        heap_start = sys_brk(0);
        heap_top = heap_start;
    }
    int ptr;
    ptr = heap_top;
    int new_top;
    new_top = ptr + size;
    int res;
    res = sys_brk(new_top);
    if (res != new_top) { return 0; } // Failed
    heap_top = new_top;
    return ptr;
}

void sys_free(int ptr) {
    // No-op for simple bump allocator
}

void sys_memset(int dest, int val, int n) {
    char* d;
    d = dest;
    int i;
    i = 0;
    while (i < n) {
        *d = val;
        d = d + 1;
        i++;
    }
}

void sys_memcpy(int dest, int src, int n) {
    char* d;
    d = dest;
    char* s;
    s = src;
    int i;
    i = 0;
    while (i < n) {
        int val;
        val = *s;
        *d = val;
        d = d + 1;
        s = s + 1;
        i++;
    }
}
#endif

#ifndef __COMPY__
void sys_memset(void* dest, int val, int n) { memset(dest, val, n); }
void sys_memcpy(void* dest, void* src, int n) { memcpy(dest, src, n); }
#endif

#ifndef __COMPY__
void sys_write(void* fd, void* buf, int size) { fwrite(buf, size, 1, (FILE*)fd); }
#endif

int sys_strlen(const char* s) {
    int len;
    len = 0;
    int c;
    c = *s;
    while (c != 0) {
        len++;
        s++;
        c = *s;
    }
    return len;
}

int sys_strcmp(const char* s1, const char* s2) {
    int loop = 1;
    while (loop == 1) {
        char c1;
        c1 = *s1;
        char c2;
        c2 = *s2;
        if (c1 != c2) {
            return c1 - c2;
        }
        if (c1 == 0) {
            return 0;
        }
        s1++; s2++;
    }
    return 0;
}

int sys_strncmp(const char* s1, const char* s2, int n) {
    int i; i = 0;
    while (i < n) {
        char c1;
        c1 = *s1;
        char c2;
        c2 = *s2;
        if (c1 != c2) {
            return c1 - c2;
        }
        if (c1 == 0) {
            return 0;
        }
        s1++; s2++; i++;
    }
    return 0;
}

void sys_strcpy(char* dest, const char* src) {
    int loop = 1;
    while (loop == 1) {
        char c;
        c = *src;
        *dest = c;
        if (c == 0) {
            return;
        }
        dest++; src++;
    }
}

void sys_strncpy(char* dest, const char* src, int n) {
    int i; i = 0;
    while (i < n) {
        char c;
        c = *src;
        *dest = c;
        if (c != 0) {
            src++;
        }
        dest++; i++;
    }
}

char* sys_strchr(char* s, int c) {
    int loop = 1;
    while (loop == 1) {
        char sc;
        sc = *s;
        if (sc == c) {
            return s;
        }
        if (sc == 0) {
            return 0;
        }
        s++;
    }
    return 0;
}

char* sys_strrchr(char* s, int c) {
    char* last;
    last = 0;
    int loop = 1;
    while (loop == 1) {
        char sc;
        sc = *s;
        if (sc == c) { last = s; }
        if (sc == 0) { return last; }
        s++;
    }
    return 0;
}

char* sys_strstr(char* haystack, char* needle) {
    int loop = 1;
    while (loop == 1) {
        char h;
        h = *haystack;
        if (h == 0) {
            return 0;
        }
        
        char* h_sub;
        h_sub = haystack;
        char* n_sub;
        n_sub = needle;
        int match; match = 1;
        int loop2; loop2 = 1;
        while (loop2 == 1) {
            char n;
            n = *n_sub;
            if (n == 0) {
                break;
            }
            char hs;
            hs = *h_sub;
            if (hs != n) {
                match = 0;
                break;
            }
            h_sub++; n_sub++;
        }
        if (match == 1) {
            return haystack;
        }
        haystack++;
    }
    return 0;
}

int parse_int(char* str) {
    // Skip whitespace
    int loop = 1;
    while (loop == 1) {
        int c;
        c = *str;
        if (c == ' ') {
            str++;
            continue;
        }
        if (c == '\t') {
            str++;
            continue;
        }
        break;
    }

    if (str[0] == '0' && str[1] == 'x') {
        int val = 0;
        char *p;
        p = str;
        p = p + 2;
        while (*p) {
            val = val * 16;
            int d;
            d = *p;
            if (d >= '0' && d <= '9') {
                val = val + (d - '0');
            }
            if (d >= 'A' && d <= 'F') {
                val = val + (d - 'A' + 10);
            }
            if (d >= 'a' && d <= 'f') {
                val = val + (d - 'a' + 10);
            }
            p++;
        }
        return val;
    }
    int res = 0;
    int sign = 1;
    int i = 0;
    if (str[0] == '-') {
        sign = -1;
        i++;
    }
    while (str[i] >= '0' && str[i] <= '9') {
        res = res * 10 + (str[i] - '0');
        i++;
    }
    return res * sign;
}

// --- Control Flow Stack (für Backpatching) ---
typedef struct {
    int type; // 0=IF, 1=WHILE, 2=ELSE
    int patch_pos; // Wo wir den Exit-Jump patchen müssen
    int start_pos; // Wo die Schleife beginnt (nur für WHILE)
    int break_head; // Verkettete Liste für break-Jumps
    int continue_head; // Verkettete Liste für continue-Jumps
    int else_chain_head; // Verkettete Liste für Jumps zum Ende einer if/else if Kette
    char for_inc[2048]; // Inkrement-Code für FOR-Schleifen
    // Switch specific
    int switch_var_offset;
    int dispatch_jump_pos;
    int case_values[64];
    int case_offsets[64];
    int case_count;
    int default_offset;
} Block;
Block *block_stack;
int block_stack_idx = 0;

// --- Helper Functions ---
void emit(uint8_t b) {
    if (code_pos >= 131072) { // sizeof(code) replaced
        print("Error: Code buffer overflow\n");
        exit(1);
    }
    code[code_pos] = b;
    code_pos++;
}

void emit32(uint32_t v) {
    int b;
    b = v & 255;
    emit(b);
    int v2;
    v2 = v >> 8;
    b = v2 & 255;
    emit(b);
    v2 = v >> 16;
    b = v2 & 255;
    emit(b);
    v2 = v >> 24;
    b = v2 & 255;
    emit(b);
}

void push_block(int type, int patch_pos, int start_pos) {
    if (block_stack_idx >= 2000) {
        print("Error: Block stack overflow (too many nested blocks)\n");
        exit(1);
    }
    block_stack[block_stack_idx].type = type;
    block_stack[block_stack_idx].patch_pos = patch_pos;
    block_stack[block_stack_idx].start_pos = start_pos;
    block_stack[block_stack_idx].break_head = -1; // Init list
    block_stack[block_stack_idx].continue_head = -1;
    block_stack[block_stack_idx].else_chain_head = -1;
    block_stack[block_stack_idx].for_inc[0] = '\0';
    block_stack[block_stack_idx].case_count = 0;
    block_stack[block_stack_idx].default_offset = -1;
    block_stack_idx++;
}
Block pop_block() {
    if(block_stack_idx > 0) {
        block_stack_idx--;
        return block_stack[block_stack_idx];
    }
    Block b;
    b.type = -1; // Return invalid block on error
    return b;
}

void strip(char* s) {
    char* p;
    p = s;
    int loop = 1;
    // Skip leading whitespace
    while (loop == 1) {
        int c;
        c = *p;
        if (c == ' ') { p++; continue; }
        if (c == '\t') { p++; continue; }
        break;
    }
    
    if (p != s) {
        int len;
        len = sys_strlen(p);
        sys_memcpy(s, p, len + 1); // Safe for left shift
    }
    
    int len;
    len = sys_strlen(s);
    // Trim trailing whitespace
    while (len > 0) {
        int idx;
        idx = len - 1;
        char* ptr;
        ptr = s + idx;
        int c;
        c = *ptr;
        
        if (c == ' ') { *ptr = 0; len--; continue; }
        if (c == '\t') { *ptr = 0; len--; continue; }
        if (c == '\n') { *ptr = 0; len--; continue; }
        if (c == '\r') { *ptr = 0; len--; continue; }
        break;
    }
}

// Helper to resolve patch chain (linked list of jumps)
void resolve_patch_chain(int head_pos, int target_pos) {
    int current = head_pos;
    while (current != -1) {
        int next = code[current] | (code[current+1] << 8) | (code[current+2] << 16) | (code[current+3] << 24);
        int rel = target_pos - (current + 4);
        code[current] = rel & 0xFF;
        code[current+1] = (rel >> 8) & 0xFF;
        code[current+2] = (rel >> 16) & 0xFF;
        code[current+3] = (rel >> 24) & 0xFF;
        current = next;
    }
}

// Helper to find string outside of quotes
char* find_code(char* line, const char* token) {
    char* p = line;
    int in_string = 0;
    size_t token_len = strlen(token);
    while (*p) {
        if (*p == '"') in_string = !in_string;
        if (!in_string && sys_strncmp(p, token, token_len) == 0) {
            return p;
        }
        p++;
    }
    return NULL;
}

int get_var_type(const char* name);

int get_var_offset(const char* name) {
    char buf[64]; sys_strncpy(buf, name, 63); buf[63]=0;
    char* dot = sys_strchr(buf, '.');
    if (dot) {
        *dot = 0;
        char* member = dot + 1;
        int base_off = get_var_offset(buf);
        int type = get_var_type(buf);
        if (type >= 100) {
            int s_idx = type - 100;
            for(int i=0; i<structs[s_idx].member_count; i++) {
                if(sys_strcmp(structs[s_idx].members[i].name, member) == 0) {
                    return base_off + structs[s_idx].members[i].offset;
                }
            }
        }
    }
    for(int i=0; i<symbol_count; i++) {
        if(sys_strcmp(symbols[i].name, name) == 0) {
            if (g_debuglevel) { print("// Resolved "); print(name); print(" to offset "); print(symbols[i].stack_offset); }
            return symbols[i].stack_offset;
        }
    }
    // Check Globals
    for(int i=0; i<global_count; i++) {
        if(sys_strcmp(globals[i].name, name) == 0) return globals[i].address;
    }
    print("Error on line "); print(current_line); print(": Variable '"); print((char*)name); print("' not found\n"); exit(1);
}

int get_var_type(const char* name) {
    char buf[64]; sys_strncpy(buf, name, 63); buf[63]=0;
    char* dot = sys_strchr(buf, '.');
    if (dot) {
        *dot = 0;
        char* member = dot + 1;
        int type = get_var_type(buf);
        if (type >= 100) {
            int s_idx = type - 100;
            for(int i=0; i<structs[s_idx].member_count; i++) {
                if(sys_strcmp(structs[s_idx].members[i].name, member) == 0) {
                    return structs[s_idx].members[i].type;
                }
            }
        }
    }
    for(int i=0; i<symbol_count; i++) {
        if(sys_strcmp(symbols[i].name, name) == 0) return symbols[i].type;
    }
    for(int i=0; i<global_count; i++) {
        if(sys_strcmp(globals[i].name, name) == 0) return globals[i].type;
    }
    return 0; // Default to int
}

void add_var(const char* name, int type) {
    if (symbol_count >= 2000) {
        print("Error: Too many variables\n");
        exit(1);
    }
    // Align to 4 bytes for simplicity, even for char
    current_stack -= 4; 
    sys_strncpy(symbols[symbol_count].name, name, 31);
    symbols[symbol_count].name[31] = '\0';
    symbols[symbol_count].stack_offset = current_stack;
    symbols[symbol_count].type = type;
    symbol_count++;
}

void add_array(const char* name, int size, int type) {
    if (is_inside_func) {
        if (symbol_count >= 2000) {
            print("Error: Too many variables\n");
            exit(1);
        }
        int bytes;
        if (type == 1) bytes = size;
        else if (type >= 100) bytes = size * structs[type-100].size;
        else bytes = size * 4;

        // Align stack to 4 bytes
        if (bytes % 4 != 0) bytes += (4 - (bytes % 4));
        
        current_stack -= bytes;
        sys_strncpy(symbols[symbol_count].name, name, 31);
        symbols[symbol_count].name[31] = '\0';
        symbols[symbol_count].stack_offset = current_stack;
        symbols[symbol_count].type = type;
        symbol_count++;
    } else {
        // Global Array
        if (global_count >= 2000) { print("Error: Too many globals\n"); exit(1); }
        for(int i=0; i<global_count; i++) {
            if(sys_strcmp(globals[i].name, name) == 0) return; // Already exists
        }
        sys_strncpy(globals[global_count].name, name, 31);
        globals[global_count].name[31] = '\0';
        
        globals[global_count].address = 0x08060000 + global_mem_offset;
        globals[global_count].type = type;
        
        int bytes;
        if (type == 1) bytes = size;
        else if (type >= 100) bytes = size * structs[type-100].size;
        else bytes = size * 4;

        if (bytes % 4 != 0) bytes += (4 - (bytes % 4));
        
        global_mem_offset += bytes;
        global_count++;
    }
}

void add_param(const char* name) {
    if (symbol_count >= 2000) {
        print("Error: Too many variables\n");
        exit(1);
    }
    sys_strncpy(symbols[symbol_count].name, name, 31);
    symbols[symbol_count].name[31] = '\0';
    symbols[symbol_count].stack_offset = current_param_offset;
    symbols[symbol_count].type = 0; // Params are always int (pushed as 4 bytes)
    current_param_offset += 4;
    symbol_count++;
}

void add_global(const char* name, int type) {
    if (global_count >= 2000) { print("Error: Too many globals\n"); exit(1); }
    for(int i=0; i<global_count; i++) {
        if(sys_strcmp(globals[i].name, name) == 0) return; // Already exists
    }
    sys_strncpy(globals[global_count].name, name, 31);
    globals[global_count].name[31] = '\0';
    // Globals start at 0x08060000 (after code)
    globals[global_count].address = 0x08060000 + global_mem_offset;
    globals[global_count].type = type;
    global_mem_offset += 4;
    global_count++;
}

int get_function_index(const char* name) {
    if (function_count >= 2000) {
        print("Error: Too many functions\n");
        exit(1);
    }
    for(int i=0; i<function_count; i++) {
        if(sys_strcmp(functions[i].name, name) == 0) return i;
    }
    sys_strncpy(functions[function_count].name, name, 31);
    functions[function_count].name[31] = '\0';
    functions[function_count].address = -1;
    functions[function_count].patch_head = -1;
    int idx = function_count;
    function_count++;
    return idx;
}

int get_struct_index(const char* name) {
    for(int i=0; i<struct_count; i++) {
        if(sys_strcmp(structs[i].name, name) == 0) return i;
    }
    return -1;
}

void add_struct_var(const char* name, int struct_idx) {
    if (symbol_count >= 2000) {
        print("Error: Too many variables\n");
        exit(1);
    }
    int size = structs[struct_idx].size;
    if (size % 4 != 0) size += (4 - (size % 4)); // Align
    current_stack -= size;
    sys_strncpy(symbols[symbol_count].name, name, 31);
    symbols[symbol_count].name[31] = '\0';
    symbols[symbol_count].stack_offset = current_stack;
    symbols[symbol_count].type = 100 + struct_idx;
    symbol_count++;
}

// --- Emit Helpers for Globals vs Locals ---
void emit_load(int off) {
    if (off > 10000) { // Global (Absolute Address)
        emit(0xA1); emit32(off); // MOV EAX, [addr]
    } else { // Local (Stack Offset)
        if (off >= -128 && off <= 127) {
            emit(0x8B); emit(0x45); emit((uint8_t)off); // MOV EAX, [EBP+off8]
        } else {
            emit(0x8B); emit(0x85); emit32(off); // MOV EAX, [EBP+off32]
        }
    }
}

void emit_store(int off) {
    if (off > 10000) {
        emit(0xA3); emit32(off); // MOV [addr], EAX
    } else {
        if (off >= -128 && off <= 127) {
            emit(0x89); emit(0x45); emit((uint8_t)off); // MOV [EBP+off8], EAX
        } else {
            emit(0x89); emit(0x85); emit32(off); // MOV [EBP+off32], EAX
        }
    }
}

void emit_lea(int off) {
    if (off > 10000) {
        // Address of global is just the immediate value
        emit(0xB8); emit32(off); // MOV EAX, imm32
    } else {
        if (off >= -128 && off <= 127) {
            emit(0x8D); emit(0x45); emit((uint8_t)off); // LEA EAX, [EBP+off8]
        } else {
            emit(0x8D); emit(0x85); emit32(off); // LEA EAX, [EBP+off32]
        }
    }
}

void emit_cmp_mem_imm(int off, int val) {
    if (off > 10000) {
        emit(0x81); emit(0x3D); emit32(off); emit32(val); // CMP [addr], imm32
    } else {
        if (off >= -128 && off <= 127) {
            emit(0x81); emit(0x7D); emit((uint8_t)off); emit32(val); // CMP [EBP+off8], imm32
        } else {
            emit(0x81); emit(0xBD); emit32(off); emit32(val); // CMP [EBP+off32], imm32
        }
    }
}

void emit_cmp_eax_mem(int off) {
    if (off > 10000) {
        emit(0x3B); emit(0x05); emit32(off); // CMP EAX, [addr]
    } else {
        if (off >= -128 && off <= 127) {
            emit(0x3B); emit(0x45); emit((uint8_t)off); // CMP EAX, [EBP+off8]
        } else {
            emit(0x3B); emit(0x85); emit32(off); // CMP EAX, [EBP+off32]
        }
    }
}

// Helper for binary ops (ADD, SUB, AND, OR, XOR)
void emit_op_eax_mem(uint8_t opcode, int off) {
    if (off > 10000) {
        emit(opcode); emit(0x05); emit32(off); // OP EAX, [addr]
    } else {
        if (off >= -128 && off <= 127) {
            emit(opcode); emit(0x45); emit((uint8_t)off); // OP EAX, [EBP+off8]
        } else {
            emit(opcode); emit(0x85); emit32(off); // OP EAX, [EBP+off32]
        }
    }
}

// Helper to parse arguments manually (replaces strtok)
// Handles nested parentheses to avoid splitting inside function calls
int parse_arguments(char* buf, char** args, int max_args) {
    int count = 0;
    char* p = buf;
    char* start = p;
    int paren_depth = 0;
    if (!*p) return 0;
    
    while (*p && count < max_args) {
        if (*p == '(') paren_depth++;
        else if (*p == ')') paren_depth--;
        
        if (*p == ',' && paren_depth == 0) {
            *p = '\0';
            strip(start);
            args[count++] = start;
            start = p + 1;
        }
        p++;
    }
    if (count < max_args) { strip(start); args[count++] = start; }
    return count;
}

void emit_print_eax() {
    // push eax, ebx, ecx, edx, esi, edi
    emit(0x50); emit(0x53); emit(0x51); emit(0x52); emit(0x56); emit(0x57);
    
    // mov ecx, esp; sub esp, 16; mov esi, ecx
    emit(0x89); emit(0xE1); emit(0x83); emit(0xEC); emit(0x10); emit(0x89); emit(0xCE);
    
    // dec esi; mov byte [esi], 10 (newline)
    emit(0x4E); emit(0xC6); emit(0x06); emit(0x0A);
    
    // test eax, eax; jnz +6 (skip zero handling)
    emit(0x85); emit(0xC0); emit(0x75); emit(0x06);
    
    // Zero case: dec esi; mov byte [esi], '0'; jmp +37 (to print)
    emit(0x4E); emit(0xC6); emit(0x06); emit(0x30); emit(0xEB); emit(0x25);
    
    // .init_convert: mov edi, eax; test eax, eax; jns +2; neg eax
    emit(0x89); emit(0xC7); emit(0x85); emit(0xC0); emit(0x79); emit(0x02); emit(0xF7); emit(0xD8);
    
    // mov ebx, 10
    emit(0xBB); emit32(10);
    
    // .convert_loop: test eax, eax; jz +12 (to check_sign)
    emit(0x85); emit(0xC0); emit(0x74); emit(0x0C);
    
    // xor edx, edx; div ebx; add dl, '0'; dec esi; mov [esi], dl; jmp -16 (loop)
    emit(0x31); emit(0xD2); emit(0xF7); emit(0xF3); emit(0x80); emit(0xC2); emit(0x30);
    emit(0x4E); emit(0x88); emit(0x16); emit(0xEB); emit(0xF0);
    
    // .check_sign: test edi, edi; jns +4 (to print)
    emit(0x85); emit(0xFF); emit(0x79); emit(0x04);
    
    // dec esi; mov byte [esi], '-'
    emit(0x4E); emit(0xC6); emit(0x06); emit(0x2D);
    
    // .do_print: mov edx, ecx; sub edx, esi; mov ecx, esi; mov ebx, 1; mov eax, 4; int 0x80
    emit(0x89); emit(0xCA); emit(0x29); emit(0xF2); emit(0x89); emit(0xF1);
    emit(0xBB); emit32(1); emit(0xB8); emit32(4); emit(0xCD); emit(0x80);
    
    // add esp, 16; pop edi, esi, edx, ecx, ebx, eax
    emit(0x83); emit(0xC4); emit(0x10);
    emit(0x5F); emit(0x5E); emit(0x5A); emit(0x59); emit(0x5B); emit(0x58);
}

void emit_return() {
    if (is_inside_main) {
        // exit(eax)
        emit(0x89); emit(0xC3); // mov ebx, eax
        emit(0xB8); emit32(1);  // mov eax, 1
        emit(0xCD); emit(0x80); // int 0x80
    } else {
        // Epilogue: mov esp, ebp; pop ebp; ret
        emit(0x89); emit(0xEC);
        emit(0x5D);
        emit(0xC3);
    }
}

// Helper to evaluate constant expressions (e.g. 128 * 1024)
int eval_const_expr(char* expr) {
    int v1 = 0, v2 = 0;
    char op = 0;
    char* p = expr;
    while (*p) {
        if (*p == '*' || *p == '+' || *p == '-' || *p == '/') {
            op = *p;
            *p = '\0'; // Split string
            v1 = parse_int(expr);
            v2 = parse_int(p + 1);
            break;
        }
        p++;
    }
    if (op == 0) return parse_int(expr);
    
    if (op == '*') return v1 * v2;
    if (op == '+') return v1 + v2;
    if (op == '-') return v1 - v2;
    if (op == '/') return (v2 != 0) ? v1 / v2 : 0;
    return 0;
}

// Helper to calculate address of arr[idx].member into EBX
// Returns member type
int emit_struct_array_addr(char* arr_name, char* idx_str, char* member_name) {
    int arr_off = get_var_offset(arr_name);
    int arr_type = get_var_type(arr_name);
    
    if (arr_type < 100) { print("Error on line "); print(current_line); print(": Not a struct array: "); print(arr_name); print("\n"); exit(1); }
    int s_idx = arr_type - 100;
    int elem_size = structs[s_idx].size;
    
    int member_offset = -1;
    int member_type = 0;
    for(int i=0; i<structs[s_idx].member_count; i++) {
        if(sys_strcmp(structs[s_idx].members[i].name, member_name) == 0) {
            member_offset = structs[s_idx].members[i].offset;
            member_type = structs[s_idx].members[i].type;
            break;
        }
    }
    if (member_offset == -1) { print("Error on line "); print(current_line); print(": Member not found: "); print(member_name); print("\n"); exit(1); }

    // 1. Load Base Address of Array into EBX
    emit_lea(arr_off); // EAX = Base
    emit(0x89); emit(0xC3); // MOV EBX, EAX

    // 2. Calculate Offset for Index
    if (isdigit(idx_str[0]) || (idx_str[0] == '-' && isdigit(idx_str[1]))) {
        int idx = parse_int(idx_str);
        emit(0x81); emit(0xC3); emit32(idx * elem_size); // ADD EBX, imm32
    } else {
        int idx_off = get_var_offset(idx_str);
        emit_load(idx_off); // EAX = index
        // IMUL EAX, elem_size
        emit(0x69); emit(0xC0); emit32(elem_size);
        // ADD EBX, EAX
        emit(0x01); emit(0xC3);
    }

    // 3. Add Member Offset
    if (member_offset > 0) {
        emit(0x81); emit(0xC3); emit32(member_offset); // ADD EBX, imm32
    }
    
    return member_type;
}

// --- Compile Line Logic ---
void compile_line(char* line) {
    char v1[128], v2[128], v3[128], v4[128];
    char op1[32], op2[32], log[32];
    char str_buf[1024]; // Reduziert auf 1KB
    char init_stmt[256]; // Reduziert
    int val;
    char params[1024]; params[0] = 0;
    str_buf[0] = 0; // Ensure buffer is clean

        // Kommentare entfernen (unter Berücksichtigung von Strings)
        char *p = line;
        int in_string = 0;
        while (*p) {
            if (*p == '"') in_string = !in_string;
            if (!in_string && *p == '/' && *(p+1) == '/') {
                *p = '\0';
                break;
            }
            p++;
        }

        // Leere Zeilen überspringen
        char *check = line;
        while (*check == ' ' || *check == '\t' || *check == '\n' || *check == '\r') check++;
        if (*check == '\0') return;

        // 0. Inside Struct Definition
        if (is_parsing_struct) {
            if (sys_strstr(line, "}")) {
                char name[32];
                if (sscanf(line, " } %31[^;];", name) == 1) {
                    strip(name);
                    sys_strcpy(structs[current_struct_def].name, name);
                    current_struct_def = -1;
                    is_parsing_struct = 0;
                }
            } else {
                char type[32], name[32];
                if (sscanf(line, " %31s %31[^;];", type, name) == 2) {
                    strip(type); strip(name);
                    int size = 4; // Default int
                    int m_type = 0;
                    if (sys_strcmp(type, "char") == 0 || sys_strcmp(type, "uint8_t") == 0) { size = 1; m_type = 1; }
                    if (sys_strcmp(type, "uint16_t") == 0) { size = 2; }
                    
                    int array_size = 1;
                    char* bracket = sys_strchr(name, '[');
                    if (bracket) { *bracket = 0; array_size = parse_int(bracket + 1); }

                    // Align members to 4 bytes for simplicity in this compiler
                    if (size < 4) size = 4; 
                    
                    int idx = structs[current_struct_def].member_count;
                    structs[current_struct_def].member_count++;
                    sys_strcpy(structs[current_struct_def].members[idx].name, name);
                    structs[current_struct_def].members[idx].type = m_type;
                    structs[current_struct_def].members[idx].offset = structs[current_struct_def].size;
                    structs[current_struct_def].size += size * array_size;
                }
            }
            return;
        }

        // 1. Function Definition: void func() { OR int func() {
        if (sys_strstr(line, "{") && (
            sscanf(line, " void %127[^(](%1023[^)])", v1, params) >= 1 || 
            sscanf(line, " int %127[^(](%1023[^)])", v1, params) >= 1 ||
            sscanf(line, " char * %127[^(](%1023[^)])", v1, params) >= 1)) {
            strip(v1);
            if (sys_strcmp(v1, "main") == 0) {
                is_inside_main = 1;
                is_inside_func = 1;
                main_addr = code_pos;
            } else {
                is_inside_main = 0;
                is_inside_func = 1;
                int idx = get_function_index(v1);
                functions[idx].address = code_pos;
                resolve_patch_chain(functions[idx].patch_head, code_pos);
                functions[idx].patch_head = -1;
            }
            // Reset locals for new function scope
            symbol_count = 0;
            current_stack = 0;
            current_param_offset = 8; // [EBP+8] First Parameter (cdecl)

            // Parse parameters
            if (params[0]) {
                char* arg_ptrs[32];
                int arg_count = parse_arguments(params, arg_ptrs, 32);
                for(int i=0; i<arg_count; i++) {
                    char type[32], name[32];
                    char* p = arg_ptrs[i];
                    // Skip 'const' keyword to allow self-hosting with const-correct functions
                    if (sys_strncmp(p, "const ", 6) == 0) {
                        p += 6;
                        while (*p == ' ') p++;
                    }
                    if (sscanf(p, " %31s %31s", type, name) == 2) {
                        char* ptr = sys_strchr(name, '*'); if(ptr) *ptr = 0;
                        add_param(name);
                    }
                }
            }
            // Prologue: push ebp; mov ebp, esp; sub esp, 256 (Safe size)
            // 81 EC <imm32> = SUB ESP, imm32
            emit(0x55); emit(0x89); emit(0xE5); emit(0x81); emit(0xEC); emit32(256);

            // Check for one-liner function (e.g. dummy sys_brk)
            if (sys_strstr(line, "}")) {
                is_inside_func = 0;
            }
        }
        // 1b. Typedef Struct Start
        else if (sys_strstr(line, "typedef struct") && sys_strstr(line, "{")) {
             if (struct_count >= 10) { print("Error on line "); print(current_line); print(": Too many structs\n"); exit(1); }
             current_struct_def = struct_count;
             struct_count++;
             structs[current_struct_def].member_count = 0;
             structs[current_struct_def].size = 0;
             is_parsing_struct = 1;
             return;
        }
        // 2c. Pointer Declaration (Generalized): Type *p;
        else if (sys_strchr(line, '*') && !sys_strchr(line, '=') && !sys_strchr(line, '[') && sscanf(line, " %31[^*] * %31[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int type = 0;
            if (sys_strcmp(v1, "int") == 0 || sys_strcmp(v1, "uint32_t") == 0) type = 3; // Int Ptr
            else if (sys_strcmp(v1, "char") == 0 || sys_strcmp(v1, "uint8_t") == 0) type = 2; // Byte Ptr
            else {
                int s_idx = get_struct_index(v1);
                if (s_idx != -1) type = 200 + s_idx; // 200+ = Pointer to Struct
                else {
                    // Fallback/Error or char* handled later?
                    // For now default to int* if unknown, but print warning
                    if (sys_strcmp(v1, "void") != 0) { // void* is generic
                         print("Warning on line "); print(current_line); print(": Unknown pointer type, assuming int*\n");
                    }
                }
            }
            if (is_inside_func) add_var(v2, type);
            else add_global(v2, type);
        }
        // 2e. String Pointer Declaration: char *s = "hello";
        else if (sys_strstr(line, "char *") && sscanf(line, " char * %127[^ =] = \"%1023[^\"]\";", v1, str_buf) == 2) {
            strip(v1);
            
            // Parse escapes (Hex \xHH support for ELF Magic)
            char parsed[1024];
            int p_len = 0;
            int i;
            for(i=0; str_buf[i]; i++) {
                if(str_buf[i] == '\\') {
                    if(str_buf[i+1] == 'x') {
                        // Hex \xHH
                        int h1 = str_buf[i+2];
                        int h2 = str_buf[i+3];
                        
                        if(h1 >= '0' && h1 <= '9') h1 -= '0';
                        else if(h1 >= 'A' && h1 <= 'F') h1 -= 'A' - 10;
                        else if(h1 >= 'a' && h1 <= 'f') h1 -= 'a' - 10;
                        
                        if(h2 >= '0' && h2 <= '9') h2 -= '0';
                        else if(h2 >= 'A' && h2 <= 'F') h2 -= 'A' - 10;
                        else if(h2 >= 'a' && h2 <= 'f') h2 -= 'a' - 10;
                        
                        parsed[p_len] = (h1 << 4) | h2;
                        p_len++;
                        i = i + 3;
                    } else if (str_buf[i+1] == 'n') {
                        parsed[p_len] = 10;
                        p_len++;
                        i++;
                    } else {
                        parsed[p_len] = str_buf[i+1];
                        p_len++;
                        i++;
                    }
                } else {
                    parsed[p_len] = str_buf[i];
                    p_len++;
                }
            }

            emit(0xE9); emit32(p_len + 1); // Jump over string + null
            uint32_t addr = 0x08048000 + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + code_pos;
            for (int j = 0; j < p_len; j++) emit(parsed[j]);
            emit(0); // Null terminator
            
            // 2. Create var and store address
            add_var(v1, 0);
            int off = get_var_offset(v1);
            emit(0xC7); emit(0x45); emit((uint8_t)off); emit32(addr); // mov [ebp+off], addr
        }
        // 2d. Array Declaration: int arr[10];
        else if (sys_strstr(line, "[") && sscanf(line, " int %127[^ [ ] [ %127[^]] ];", v1, v2) == 2) {
            strip(v1);
            int val = eval_const_expr(v2);
            if (val <= 0) { print("Error on line "); print(current_line); print(": Invalid array size\n"); exit(1); }
            add_array(v1, val, 0);
        }
        // 2d. Char/Byte Array Declaration: char arr[10]; OR uint8_t arr[10];
        else if (sys_strstr(line, "[") && (sscanf(line, " char %127[^ [ ] [ %127[^]] ];", v1, v2) == 2 || sscanf(line, " uint8_t %127[^ [ ] [ %127[^]] ];", v1, v2) == 2)) {
            strip(v1);
            int val = eval_const_expr(v2);
            if (val <= 0) { print("Error on line "); print(current_line); print(": Invalid array size\n"); exit(1); }
            add_array(v1, val, 1); // Type 1 = Byte
        }
        // 2d. Struct Array Declaration: MyStruct arr[10];
        else if (sys_strstr(line, "[") && sscanf(line, " %31s %127[^ [ ] [ %127[^]] ];", v1, v2, v3) == 3) {
             int s_idx = get_struct_index(v1);
             if (s_idx != -1) {
                 strip(v2);
                 int count = eval_const_expr(v3);
                 if (count <= 0) { print("Error on line "); print(current_line); print(": Invalid array size\n"); exit(1); }
                 add_array(v2, count, 100 + s_idx);
             }
        }
        // 2x. Global Declaration with Init (Robust): type name = ...;
        else if (!is_inside_func && (sys_strstr(line, "int ") || sys_strstr(line, "uint32_t ") || sys_strstr(line, "char ") || sys_strstr(line, "uint8_t ")) && sys_strstr(line, "=") && !sys_strchr(line, '*') && sscanf(line, " %31s %127[^=]=", v1, v2) == 2) {
            strip(v1); strip(v2);
            int type = 0;
            if (sys_strcmp(v1, "char") == 0 || sys_strcmp(v1, "uint8_t") == 0) type = 1;
            
            // Register global, ignore value for now (init to 0)
            add_global(v2, type);
        }
        // 2. Declaration: int a = 10; OR int a = 'c'; OR int a = b;
        else if (sys_strstr(line, "int ") && sys_strstr(line, "=") && sscanf(line, " int %127[^ =] = %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int val = 0;
            int is_const = 0;
            
            if (v2[0] == '\'') { val = v2[1]; is_const = 1; } // Char literal
            else if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1]))) { val = parse_int(v2); is_const = 1; }
            
            if (is_inside_func) {
                add_var(v1, 0);
                int off = get_var_offset(v1);
                if (is_const) {
                    emit(0xC7); emit(0x45); emit((uint8_t)off); emit32(val);
                } else {
                    int src_off = get_var_offset(v2);
                    emit_load(src_off);
                    emit_store(off);
                }
            } else {
                if (!is_const) { print("Error on line "); print(current_line); print(": Global init must be constant\n"); exit(1); }
                // Quick hack for globals: only support int constants for now in this simple parser
                print("Warning: Global init only partially supported (use assignment in main): "); print(line);
                add_global(v1, 0);
            }
        }
        // 2a. Declaration without init: int a;
        else if (sys_strstr(line, ";") && sscanf(line, " int %127[^;];", v1) == 1) {
            strip(v1);
            if (is_inside_func) add_var(v1, 0);
            else add_global(v1, 0);
        }
        // 2a2. Declaration without init: char a;
        else if (sys_strstr(line, ";") && sscanf(line, " char %127[^;];", v1) == 1) {
            strip(v1);
            if (is_inside_func) add_var(v1, 1);
            else add_global(v1, 1);
        }
        // 2g. uint32_t/uint8_t Declaration with Init
        else if ((sys_strstr(line, "uint32_t ") || sys_strstr(line, "uint8_t ")) && sys_strstr(line, "=") && sscanf(line, " %31s %127[^=] = %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int type = (sys_strcmp(v1, "uint8_t") == 0) ? 1 : 0;
            int val = 0;
            int is_const = 0;
            if (v3[0] == '\'') { val = v3[1]; is_const = 1; }
            else if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1]))) { val = parse_int(v3); is_const = 1; }

            if (is_inside_func) {
                add_var(v2, type);
                int off = get_var_offset(v2);
                if (is_const) {
                    emit(0xC7); emit(0x45); emit((uint8_t)off); emit32(val);
                } else {
                    int src_off = get_var_offset(v3);
                    emit_load(src_off);
                    emit_store(off);
                }
            } else {
                add_global(v2, type);
            }
        }
        // 2h. uint32_t/uint8_t Declaration without Init
        else if ((sys_strstr(line, "uint32_t ") || sys_strstr(line, "uint8_t ")) && sscanf(line, " %31s %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int type = (sys_strcmp(v1, "uint8_t") == 0) ? 1 : 0;
            if (is_inside_func) add_var(v2, type);
            else add_global(v2, type);
        }
        // 2f. Struct Variable Declaration: MyStruct s;
        else if (sscanf(line, " %31s %31[^;];", v1, v2) == 2 && get_struct_index(v1) != -1) {
             strip(v1); strip(v2);
             add_struct_var(v2, get_struct_index(v1));
             return;
        }
        // 19. Address Of: p = &a;
        else if (sys_strstr(line, "&") && sscanf(line, " %127[^ =] = & %127[^;]", v1, v2) == 2) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            
            emit_lea(src_off); // Load address of src into EAX
            emit_store(dest_off); // Store EAX into dest
        }
        // 20. Dereference Write: *p = 5;
        else if (sys_strstr(line, "*") && sscanf(line, " * %127[^ =] = %d;", v1, &val) == 2) {
            // v1 enthält den Variablennamen (ohne *)
            strip(v1);
            int ptr_off = get_var_offset(v1);
            
            emit_load(ptr_off); // Load pointer address into EAX
            
            // mov dword [eax], val -> C7 00 <imm32>
            emit(0xC7); emit(0x00); emit32(val);
        }
        // 20b. Dereference Write Var: *p = a;
        else if (sys_strstr(line, "*") && sscanf(line, " * %127[^ =] = %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int ptr_off = get_var_offset(v1);
            int val_off = get_var_offset(v2);
            int type = get_var_type(v1);
            
            // Load pointer into EBX
            emit_load(ptr_off);
            emit(0x89); emit(0xC3); // MOV EBX, EAX
            
            // Load value into EAX
            emit_load(val_off);
            
            if (type == 2) { // Byte Ptr
                emit(0x88); emit(0x03); // MOV [EBX], AL
            } else {
                emit(0x89); emit(0x03); // MOV [EBX], EAX
            }
        }
        // 22. Dereference Read: a = *p;
        else if (sys_strstr(line, "*") && sscanf(line, " %127[^ =] = * %127[^;]", v1, v2) == 2) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            int ptr_off = get_var_offset(v2);
            int ptr_type = get_var_type(v2);
            
            emit_load(ptr_off); // Load pointer into EAX
            
            if (ptr_type == 2) { // Byte Ptr (char*)
                // mov al, [eax] -> 8A 00
                emit(0x8A); emit(0x00);
                // and eax, 0xFF
                emit(0x25); emit32(0xFF);
            } else {
                // mov eax, [eax] -> 8B 00
                emit(0x8B); emit(0x00);
            }
            emit_store(dest_off);
        }
        // 23. Arrow Read: a = p->x;
        else if (sys_strstr(line, "->") && sscanf(line, " %127[^ =] = %127[^-]->%127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            int ptr_off = get_var_offset(v2);
            int ptr_type = get_var_type(v2);
            
            if (ptr_type < 200) { print("Error on line "); print(current_line); print(": Not a struct pointer: "); print(v2); print("\n"); exit(1); }
            int s_idx = ptr_type - 200;
            int member_offset = -1;
            int member_type = 0;
            for(int i=0; i<structs[s_idx].member_count; i++) {
                if(sys_strcmp(structs[s_idx].members[i].name, v3) == 0) {
                    member_offset = structs[s_idx].members[i].offset;
                    member_type = structs[s_idx].members[i].type;
                    break;
                }
            }
            if (member_offset == -1) { print("Error on line "); print(current_line); print(": Member not found: "); print(v3); print("\n"); exit(1); }

            emit_load(ptr_off); // EAX = Address of struct
            emit(0x05); emit32(member_offset); // ADD EAX, offset
            
            // Dereference: MOV EAX, [EAX]
            if (member_type == 1) { // char/byte
                emit(0x8A); emit(0x00); // MOV AL, [EAX]
                emit(0x25); emit32(0xFF); // AND EAX, 0xFF
            } else {
                emit(0x8B); emit(0x00); // MOV EAX, [EAX]
            }
            emit_store(dest_off);
        }
        // 24. Arrow Write: p->x = a;
        else if (sys_strstr(line, "->") && sscanf(line, " %127[^-]->%127[^ =] = %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int ptr_off = get_var_offset(v1);
            int ptr_type = get_var_type(v1);
            
            if (ptr_type < 200) { print("Error on line "); print(current_line); print(": Not a struct pointer: "); print(v1); print("\n"); exit(1); }
            int s_idx = ptr_type - 200;
            int member_offset = -1;
            int member_type = 0;
            for(int i=0; i<structs[s_idx].member_count; i++) {
                if(sys_strcmp(structs[s_idx].members[i].name, v2) == 0) {
                    member_offset = structs[s_idx].members[i].offset;
                    member_type = structs[s_idx].members[i].type;
                    break;
                }
            }
            if (member_offset == -1) { print("Error on line "); print(current_line); print(": Member not found: "); print(v2); print("\n"); exit(1); }

            emit_load(ptr_off); // EAX = Address
            emit(0x05); emit32(member_offset); // ADD EAX, offset
            emit(0x89); emit(0xC3); // MOV EBX, EAX (Target Addr)
            
            // Load Value (v3) -> EAX
            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1])) || v3[0] == '\'') {
                int val = 0;
                if (v3[0] == '\'') val = v3[1];
                else val = parse_int(v3);
                emit(0xB8); emit32(val); // MOV EAX, imm32
            } else {
                int val_off = get_var_offset(v3);
                emit_load(val_off);
            }
            
            // Store: MOV [EBX], EAX
            if (member_type == 1) {
                emit(0x88); emit(0x03); // MOV [EBX], AL
            } else {
                emit(0x89); emit(0x03); // MOV [EBX], EAX
            }
        }
        // Syscall: fopen(filename, mode) -> returns fd
        else if (sys_strstr(line, "fopen") && sscanf(line, " %127[^ =] = fopen ( %127[^,], %127[^)] );", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            
            // Arg 1: Filename (v2) -> EBX
            if (v2[0] == '"') {
                // String literal handling not fully implemented for fopen in this snippet, 
                // assuming variable for bootstrapping (e.g. argv[1] assigned to var)
                print("Error on line "); print(current_line); print(": fopen requires variable as filename for now\n"); exit(1);
            } else {
                int off = get_var_offset(v2);
                emit_load(off);
                emit(0x89); emit(0xC3); // MOV EBX, EAX
            }
            
            // Arg 2: Mode (v3) -> ECX (Flags), EDX (Mode)
            // Assume "r" -> O_RDONLY (0)
            emit(0x31); emit(0xC9); // XOR ECX, ECX
            emit(0x31); emit(0xD2); // XOR EDX, EDX
            
            emit(0xB8); emit32(5); // MOV EAX, 5 (SYS_OPEN)
            emit(0xCD); emit(0x80); // INT 0x80
            
            emit_store(dest_off);
        }
        // Syscall: fgetc(fd) -> returns char or -1
        else if (sys_strstr(line, "fgetc") && sscanf(line, " %127[^ =] = fgetc ( %127[^)] );", v1, v2) == 2) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            int fd_off = get_var_offset(v2);
            
            emit_load(fd_off);
            emit(0x89); emit(0xC3); // MOV EBX, EAX
            
            // Buffer on stack (1 byte)
            emit(0x6A); emit(0x00); // PUSH 0
            emit(0x89); emit(0xE1); // MOV ECX, ESP
            
            emit(0xBA); emit32(1);  // MOV EDX, 1
            emit(0xB8); emit32(3);  // MOV EAX, 3 (SYS_READ)
            emit(0xCD); emit(0x80); // INT 0x80
            
            // Check result (EAX == 1 means success)
            emit(0x83); emit(0xF8); emit(0x01); // CMP EAX, 1
            emit(0x75); emit(0x08); // JNE +8 (Skip success block)
            
            emit(0x58); // POP EAX (Get byte)
            emit(0x25); emit32(0xFF); // AND EAX, 0xFF
            emit(0xEB); emit(0x06); // JMP +6 (Skip EOF block)
            
            // EOF case
            emit(0x58); // POP EAX (Clean stack)
            emit(0xB8); emit32(-1); // MOV EAX, -1
            
            emit_store(dest_off);
        }
        // Syscall: fclose(fd)
        else if (sys_strstr(line, "fclose") && sscanf(line, " fclose ( %127[^)] );", v1) == 1) {
            strip(v1);
            int fd_off = get_var_offset(v1);
            emit_load(fd_off);
            emit(0x89); emit(0xC3); // MOV EBX, EAX
            emit(0xB8); emit32(6); // MOV EAX, 6 (SYS_CLOSE)
            emit(0xCD); emit(0x80); // INT 0x80
        }
        // Syscall: sys_brk(addr) -> returns new_brk
        else if (sys_strstr(line, "sys_brk") && sscanf(line, " %127[^ =] = sys_brk ( %127[^)] );", v1, v2) == 2) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            
            // Arg 1: addr (v2) -> EBX
            if (isdigit(v2[0])) {
                emit(0xBB); emit32(parse_int(v2));
            } else {
                int off = get_var_offset(v2);
                emit_load(off);
                emit(0x89); emit(0xC3); // MOV EBX, EAX
            }
            
            emit(0xB8); emit32(45); // MOV EAX, 45 (SYS_BRK)
            emit(0xCD); emit(0x80); // INT 0x80
            
            emit_store(dest_off);
        }
        // Syscall: exit(code)
        else if (strstr(line, "exit") && sscanf(line, " exit ( %127[^)] );", v1) == 1) {
            strip(v1);
            if (isdigit(v1[0])) {
                 emit(0xBB); emit32(parse_int(v1));
            } else {
                 int off = get_var_offset(v1);
                 emit_load(off);
                 emit(0x89); emit(0xC3); // MOV EBX, EAX
            }
            emit(0xB8); emit32(1);   // MOV EAX, 1 (SYS_EXIT)
            emit(0xCD); emit(0x80);  // INT 0x80
        }
        // 25. Struct Array Read: x = arr[i].y;
        else if (sys_strstr(line, "].") && sscanf(line, " %127[^ =] = %127[^ [ ] [ %127[^]] ] . %127[^;];", v1, v2, v3, v4) == 4) {
            strip(v1); strip(v2); strip(v3); strip(v4);
            int dest_off = get_var_offset(v1);
            
            int member_type = emit_struct_array_addr(v2, v3, v4); // Sets EBX to address
            
            // Load Value -> EAX
            if (member_type == 1) {
                emit(0x8A); emit(0x03); // MOV AL, [EBX]
                emit(0x25); emit32(0xFF); // AND EAX, 0xFF
            } else {
                emit(0x8B); emit(0x03); // MOV EAX, [EBX]
            }
            emit_store(dest_off);
        }
        // 26. Struct Array Write: arr[i].y = x;
        else if (sys_strstr(line, "].") && sscanf(line, " %127[^ [ ] [ %127[^]] ] . %127[^ =] = %127[^;];", v1, v2, v3, v4) == 4) {
            strip(v1); strip(v2); strip(v3); strip(v4);
            
            int member_type = emit_struct_array_addr(v1, v2, v3); // Sets EBX to address
            
            // Push EBX (Target Address)
            emit(0x53);
            
            // Load Value (v4) -> EAX
            if (isdigit(v4[0]) || (v4[0] == '-' && isdigit(v4[1])) || v4[0] == '\'') {
                int val = 0;
                if (v4[0] == '\'') val = v4[1];
                else val = parse_int(v4);
                emit(0xB8); emit32(val);
            } else {
                int val_off = get_var_offset(v4);
                emit_load(val_off);
            }
            
            // Pop EBX
            emit(0x5B);
            
            // Store
            if (member_type == 1) {
                emit(0x88); emit(0x03); // MOV [EBX], AL
            } else {
                emit(0x89); emit(0x03); // MOV [EBX], EAX
            }
        }
        // 27. Struct Array Increment/Decrement: arr[i].y++;
        else if (sys_strstr(line, "].") && (sys_strstr(line, "++;") || sys_strstr(line, "--;")) && sscanf(line, " %127[^ [ ] [ %127[^]] ] . %127[^ + -];", v1, v2, v3) == 3) {
            int is_inc = sys_strstr(line, "++;") ? 1 : 0;
            strip(v1); strip(v2); strip(v3);
            
            int member_type = emit_struct_array_addr(v1, v2, v3); // Sets EBX to address
            
            if (is_inc) {
                if (member_type == 1) { emit(0xFE); emit(0x03); } // INC byte [EBX]
                else { emit(0xFF); emit(0x03); } // INC dword [EBX]
            } else {
                if (member_type == 1) { emit(0xFE); emit(0x0B); } // DEC byte [EBX]
                else { emit(0xFF); emit(0x0B); } // DEC dword [EBX]
            }
        }
        // Array Read: x = arr[i] OR x = arr[0]
        else if (sys_strstr(line, "[") && sscanf(line, " %127[^ = ] = %127[^ [ ] [ %127[^]] ];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            
            // Handle Side Effects in Index (v3)
            int post_inc = 0, pre_dec = 0;
            if (sys_strstr(v3, "++")) {
                char* p = sys_strstr(v3, "++"); *p = 0; strip(v3); post_inc = 1;
            } else if (v3[0] == '-' && v3[1] == '-') {
                memmove(v3, v3+2, strlen(v3)); strip(v3); pre_dec = 1;
            }

            if (pre_dec) {
                int off = get_var_offset(v3);
                if (off > 10000) { emit(0xFF); emit(0x0D); emit32(off); } // DEC [addr]
                else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x4D); emit((uint8_t)off); }
                else { emit(0xFF); emit(0x8D); emit32(off); }
            }

            int dest_off = get_var_offset(v1);
            int arr_off = get_var_offset(v2);
            int type = get_var_type(v2);

            if (type >= 200 || type == 2 || type == 3) {
                emit_load(arr_off); // Load pointer value -> EAX
            } else {
                emit_lea(arr_off);  // Load stack/global address -> EAX
            }
            emit(0x89); emit(0xC3); // MOV EBX, EAX

            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1]))) {
                int val = parse_int(v3);
                if (type == 1 || type == 2) { // Byte array or ptr
                    // MOV AL, [EBX + val] -> 8A 83 disp32
                    emit(0x8A); emit(0x83); emit32(val);
                    // AND EAX, 0xFF
                    emit(0x25); emit32(0xFF);
                } else { // Int array
                    // MOV EAX, [EBX + val*4] -> 8B 83 disp32
                    emit(0x8B); emit(0x83); emit32(val * 4);
                }
            } else {
                int idx_off = get_var_offset(v3);
                emit_load(idx_off);     // Load index -> EAX
                emit(0x89); emit(0xC1); // MOV ECX, EAX
                
                if (type == 1 || type == 2) { // Byte array or ptr
                    // MOV AL, [EBX + ECX] -> 8A 04 0B
                    emit(0x8A); emit(0x04); emit(0x0B);
                    // AND EAX, 0xFF
                    emit(0x25); emit32(0xFF);
                } else { // Int array
                    // SIB: MOV EAX, [EBX + ECX * 4]
                    emit(0x8B); emit(0x04); emit(0x8B);
                }
            }
            emit_store(dest_off);

            if (post_inc) {
                int off = get_var_offset(v3);
                if (off > 10000) { emit(0xFF); emit(0x05); emit32(off); } // INC [addr]
                else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x45); emit((uint8_t)off); }
                else { emit(0xFF); emit(0x85); emit32(off); }
            }
        }
        // Array Write: arr[i] = x OR arr[0] = x
        else if (sys_strstr(line, "[") && sscanf(line, " %127[^ [ ] [ %127[^]] ] = %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            
            // Handle Side Effects in Index (v2)
            int post_inc = 0, pre_dec = 0;
            if (sys_strstr(v2, "++")) {
                char* p = sys_strstr(v2, "++"); *p = 0; strip(v2); post_inc = 1;
            } else if (v2[0] == '-' && v2[1] == '-') {
                memmove(v2, v2+2, strlen(v2)); strip(v2); pre_dec = 1;
            }

            if (pre_dec) {
                int off = get_var_offset(v2);
                if (off > 10000) { emit(0xFF); emit(0x0D); emit32(off); }
                else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x4D); emit((uint8_t)off); }
                else { emit(0xFF); emit(0x8D); emit32(off); }
            }

            int arr_off = get_var_offset(v1);
            int type = get_var_type(v1);
            
            if (type >= 200 || type == 2 || type == 3) {
                emit_load(arr_off);
            } else {
                emit_lea(arr_off);
            }
            emit(0x89); emit(0xC3); // MOV EBX, EAX
            
            // 1. Calculate Target Address in EBX
            if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1]))) {
                int idx = parse_int(v2);
                int scale = (type == 1 || type == 2) ? 1 : 4;
                emit(0x81); emit(0xC3); emit32(idx * scale); // ADD EBX, imm32
            } else {
                int idx_off = get_var_offset(v2);
                emit_load(idx_off);     // Load index -> EAX
                emit(0x89); emit(0xC1); // MOV ECX, EAX
                
                if (type == 1 || type == 2) {
                    // LEA EBX, [EBX + ECX] -> 8D 1C 0B
                    emit(0x8D); emit(0x1C); emit(0x0B);
                } else {
                    // LEA EBX, [EBX + ECX * 4] -> 8D 1C 8B
                    emit(0x8D); emit(0x1C); emit(0x8B);
                }
            }

            // 2. Load Value -> EAX
            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1])) || v3[0] == '\'') {
                int val = 0;
                if (v3[0] == '\'') val = v3[1];
                else val = parse_int(v3);
                emit(0xB8); emit32(val); // MOV EAX, imm32
            } else {
                int val_off = get_var_offset(v3);
                emit_load(val_off);
            }
            
            // 3. Store
            if (type == 1 || type == 2) {
                // MOV [EBX], AL -> 88 03
                emit(0x88); emit(0x03);
            } else {
                // MOV [EBX], EAX -> 89 03
                emit(0x89); emit(0x03);
            }

            if (post_inc) {
                int off = get_var_offset(v2);
                if (off > 10000) { emit(0xFF); emit(0x05); emit32(off); }
                else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x45); emit((uint8_t)off); }
                else { emit(0xFF); emit(0x85); emit32(off); }
            }
        }
        // 3d. Modulo: a = a % 5; OR a = 10 % 3;
        else if (sscanf(line, " %127[^ =] = %127[^ %] %% %d;", v1, v2, &val) == 3) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            
            // Load v2 (variable or constant) into EAX
            if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1]))) {
                emit(0xB8); emit32(parse_int(v2));
            } else {
                int src_off = get_var_offset(v2);
                emit_load(src_off);
            }
            
            // mov ebx, val
            emit(0xBB); emit32(val);
            // cdq (sign extend eax to edx:eax)
            emit(0x99);
            // idiv ebx (edx:eax / ebx -> eax quot, edx rem)
            emit(0xF7); emit(0xFB);
            // mov [ebp-dest], edx (Remainder is in EDX)
            if (dest_off > 10000) { emit(0x89); emit(0x15); emit32(dest_off); } // MOV [addr], EDX
            else { emit(0x89); emit(0x55); emit((uint8_t)dest_off); }
        }
        // 3. Addition: a = a + 5;
        else if (sscanf(line, " %127[^ =] = %127[^ +] + %d;", v1, v2, &val) == 3) {
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            
            emit_load(src_off);
            
            // add eax, val -> 05 <imm32>
            emit(0x05); emit32(val);
            
            emit_store(dest_off);
        }
        // 3b. Subtraction: a = a - 5;
        else if (sscanf(line, " %127[^ =] = %127[^ -] - %d;", v1, v2, &val) == 3) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            
            emit_load(src_off);
            
            // sub eax, val -> 2D <imm32>
            emit(0x2D); emit32(val);
            
            emit_store(dest_off);
        }
        // 3c. Multiplication: a = a * 5;
        else if (sscanf(line, " %127[^ =] = %127[^ *] * %d;", v1, v2, &val) == 3) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            
            emit_load(src_off);
            
            // imul eax, eax, val -> 69 C0 <imm32>
            emit(0x69); emit(0xC0); emit32(val);
            
            emit_store(dest_off);
        }
        // 3e. Bitwise AND: a = b & c;
        else if (sscanf(line, " %127[^ =] = %127[^ &] & %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            emit_load(src_off);
            
            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1]))) {
                emit(0x25); emit32(parse_int(v3)); // AND EAX, imm32
            } else {
                int off3 = get_var_offset(v3);
                emit_op_eax_mem(0x23, off3); // AND
            }
            emit_store(dest_off);
        }
        // 3f. Bitwise OR: a = b | c;
        else if (sscanf(line, " %127[^ =] = %127[^ |] | %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            emit_load(src_off);
            
            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1]))) {
                emit(0x0D); emit32(parse_int(v3)); // OR EAX, imm32
            } else {
                int off3 = get_var_offset(v3);
                emit_op_eax_mem(0x0B, off3); // OR
            }
            emit_store(dest_off);
        }
        // 3g. Bitwise XOR: a = b ^ c;
        else if (sscanf(line, " %127[^ =] = %127[^ ^] ^ %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            emit_load(src_off);
            
            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1]))) {
                emit(0x35); emit32(parse_int(v3)); // XOR EAX, imm32
            } else {
                int off3 = get_var_offset(v3);
                emit_op_eax_mem(0x33, off3); // XOR
            }
            emit_store(dest_off);
        }
        // 3h. Bitwise Shift Left: a = b << c;
        else if (sscanf(line, " %127[^ =] = %127[^ <] << %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            
            // Load shift amount into ECX
            if (isdigit(v3[0])) {
                emit(0xB9); emit32(parse_int(v3)); // MOV ECX, imm32
            } else {
                int count_off = get_var_offset(v3);
                emit_load(count_off);
                emit(0x89); emit(0xC1); // MOV ECX, EAX
            }
            emit_load(src_off); // Load value into EAX
            emit(0xD3); emit(0xE0); // SHL EAX, CL
            emit_store(dest_off);
        }
        // 3i. Bitwise Shift Right: a = b >> c;
        else if (sscanf(line, " %127[^ =] = %127[^ >] >> %127[^;];", v1, v2, v3) == 3) {
            strip(v1); strip(v2); strip(v3);
            int dest_off = get_var_offset(v1);
            int src_off = get_var_offset(v2);
            
            if (isdigit(v3[0])) {
                emit(0xB9); emit32(parse_int(v3)); // MOV ECX, imm32
            } else {
                int count_off = get_var_offset(v3);
                emit_load(count_off);
                emit(0x89); emit(0xC1); // MOV ECX, EAX
            }
            emit_load(src_off); // Load value into EAX
            emit(0xD3); emit(0xF8); // SAR EAX, CL (Arithmetic Shift Right)
            emit_store(dest_off);
        }
        // 3j. Sizeof: a = sizeof(Type);
        else if (sscanf(line, " %127[^ =] = sizeof ( %127[^)] );", v1, v2) == 2) {
            strip(v1); strip(v2);
            int dest_off = get_var_offset(v1);
            int size = 0;
            
            if (sys_strcmp(v2, "int") == 0 || sys_strcmp(v2, "uint32_t") == 0) size = 4;
            else if (sys_strcmp(v2, "char") == 0 || sys_strcmp(v2, "uint8_t") == 0) size = 1;
            else if (sys_strchr(v2, '*')) size = 4;
            else {
                int s_idx = get_struct_index(v2);
                if (s_idx != -1) size = structs[s_idx].size;
                else { print("Error on line "); print(current_line); print(": Unknown type in sizeof\n"); exit(1); }
            }
            
            if (dest_off > 10000) {
                emit(0xC7); emit(0x05); emit32(dest_off); emit32(size);
            } else {
                if (dest_off >= -128 && dest_off <= 127) { emit(0xC7); emit(0x45); emit((uint8_t)dest_off); emit32(size); }
                else { emit(0xC7); emit(0x85); emit32(dest_off); emit32(size); }
            }
        }
        // 15b. Function Call Assignment: x = func();
        else if (sys_strstr(line, "=") && sys_strstr(line, "(") && sscanf(line, " %127[^ =] = %127[^(]", v1, v2) == 2) {
            // Manual argument extraction to be safe
            char* start_args = sys_strchr(line, '(');
            char* end_args = sys_strrchr(line, ')');
            if (start_args && end_args && end_args > start_args) {
                int len = end_args - (start_args + 1);
                if (len >= sizeof(str_buf)) len = sizeof(str_buf) - 1;
                strncpy(str_buf, start_args + 1, len);
                str_buf[len] = 0;
            } else {
                str_buf[0] = 0;
            }
            strip(v1); strip(v2);
            if (g_debuglevel) { print("// Assignment Call Detected: "); print(v2); print("\n"); }
            int dest_off = get_var_offset(v1);
            int idx = get_function_index(v2);
            
            // Parse Args & Push (Reverse Order)
            int arg_count = 0;
            if (str_buf[0]) {
                char* arg_ptrs[32];
                arg_count = parse_arguments(str_buf, arg_ptrs, 32);
                
                for (int i = arg_count - 1; i >= 0; i--) {
                    char* arg = arg_ptrs[i];
                    if (isdigit(arg[0]) || (arg[0] == '-' && isdigit(arg[1]))) {
                        int val = parse_int(arg);
                        if (g_debuglevel) { print("// Pushing imm32: "); print(val); }
                        if (val >= -128 && val <= 127) { emit(0x6A); emit(val & 0xFF); }
                        else { emit(0x68); emit32(val); }
                    } else {
                        int off = get_var_offset(arg);
                        if (g_debuglevel) { print("// Pushing var from offset: "); print(off); }
                        if (off >= -128 && off <= 127) { emit(0xFF); emit(0x75); emit((uint8_t)off); }
                        else { emit(0xFF); emit(0xB5); emit32(off); }
                    }
                }
            }
            emit(0xE8); // CALL
            if (functions[idx].address != -1) { emit32(functions[idx].address - (code_pos + 4)); }
            else { int patch = code_pos; emit32(functions[idx].patch_head); functions[idx].patch_head = patch; }
            if (arg_count > 0) { emit(0x83); emit(0xC4); emit(arg_count * 4); }
            
            // Store Result: mov [ebp-dest_off], eax
            emit_store(dest_off);
        }
        // 2b. General Assignment: a = 10; OR a = 'c'; OR a = b;
        // Moved AFTER arithmetic to act as fallback
        else if (sys_strstr(line, "=") && sscanf(line, " %127[^ =] = %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            // Ensure it's not a partial match of an arithmetic expression (e.g. "a = a + 5")
            if (!sys_strchr(v2, '+') && !sys_strchr(v2, '-') && !sys_strchr(v2, '*') && !sys_strchr(v2, '%') && !sys_strchr(v2, '(') && !sys_strchr(v2, '>')) {
                
                // Handle Side Effects in Source (v2) e.g. a = b++;
                int post_inc = 0, pre_dec = 0;
                if (sys_strstr(v2, "++")) {
                    char* p = sys_strstr(v2, "++"); *p = 0; strip(v2); post_inc = 1;
                } else if (v2[0] == '-' && v2[1] == '-') {
                    memmove(v2, v2+2, strlen(v2)); strip(v2); pre_dec = 1;
                }

                if (pre_dec) {
                    int off = get_var_offset(v2);
                    if (off > 10000) { emit(0xFF); emit(0x0D); emit32(off); }
                    else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x4D); emit((uint8_t)off); }
                    else { emit(0xFF); emit(0x8D); emit32(off); }
                }

                int dest_off = get_var_offset(v1);
                int val = 0;
                int is_const = 0;
                
                if (v2[0] == '\'') { val = v2[1]; is_const = 1; }
                else if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1]))) { val = parse_int(v2); is_const = 1; }
                
                if (is_const) {
                    if (dest_off > 10000) {
                        emit(0xC7); emit(0x05); emit32(dest_off); emit32(val);
                    } else {
                        emit(0xC7); emit(0x45); emit((uint8_t)dest_off); emit32(val);
                    }
                } else {
                    // Variable assignment: a = b;
                    int src_off = get_var_offset(v2);
                    emit_load(src_off);
                    emit_store(dest_off);
                }

                if (post_inc) {
                    int off = get_var_offset(v2);
                    if (off > 10000) { emit(0xFF); emit(0x05); emit32(off); }
                    else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x45); emit((uint8_t)off); }
                    else { emit(0xFF); emit(0x85); emit32(off); }
                }
            }
        }
        // 21. Increment: i++;
        else if (sys_strstr(line, "++;") && sscanf(line, " %127[^ +] ++;", v1) == 1 && sys_strcmp(v1, "if") != 0 && sys_strcmp(v1, "while") != 0 && sys_strcmp(v1, "for") != 0 && sys_strcmp(v1, "return") != 0) {
            strip(v1);
            int off = get_var_offset(v1);
            // INC [mem]
            if (off > 10000) {
                emit(0xFF); emit(0x05); emit32(off);
            } else {
                if (off >= -128 && off <= 127) { emit(0xFF); emit(0x45); emit((uint8_t)off); }
                else { emit(0xFF); emit(0x85); emit32(off); }
            }
        }
        // 22. Decrement: i--;
        else if (sys_strstr(line, "--;") && sscanf(line, " %127[^ -] --;", v1) == 1 && sys_strcmp(v1, "if") != 0 && sys_strcmp(v1, "while") != 0 && sys_strcmp(v1, "for") != 0 && sys_strcmp(v1, "return") != 0) {
            strip(v1);
            int off = get_var_offset(v1);
            // DEC [mem]
            if (off > 10000) {
                emit(0xFF); emit(0x0D); emit32(off);
            } else {
                if (off >= -128 && off <= 127) { emit(0xFF); emit(0x4D); emit((uint8_t)off); }
                else { emit(0xFF); emit(0x8D); emit32(off); }
            }
        }
        // 5. Logical AND/OR: if ( a == 1 && b == 2 )
        // WICHTIG: Muss VOR den einfachen if-Checks stehen, da sscanf sonst den Prefix matcht!
        else if (sscanf(line, " if ( %127s %31s %127s %31s %127s %31s %127[^ )] ) {", v1, op1, v3, log, v2, op2, v4) == 7) {
            strip(v1); strip(op1); strip(v3); strip(log); strip(v2); strip(op2); strip(v4);
            int off1 = get_var_offset(v1);
            int off2 = get_var_offset(v2);
            int patch_pos = -1;

            // Check 1
            if (isdigit(v3[0]) || (v3[0] == '-' && isdigit(v3[1])) || v3[0] == '\'') {
                int val1 = 0;
                if (v3[0] == '\'') {
                    if (v3[1] == '\\') {
                        if (v3[2] == 't') val1 = '\t';
                        else if (v3[2] == 'n') val1 = '\n';
                        else if (v3[2] == 'r') val1 = '\r';
                        else if (v3[2] == '0') val1 = 0;
                        else val1 = v3[2];
                    } else val1 = v3[1];
                } else val1 = parse_int(v3);
                emit_cmp_mem_imm(off1, val1);
            } else {
                int off_v3 = get_var_offset(v3);
                emit_load(off1);
                emit_cmp_eax_mem(off_v3);
            }

            if (sys_strcmp(log, "&&") == 0) {
                // AND: Both must be true. If either is false, jump to END.
                // Jump if FALSE
                if (sys_strcmp(op1, "==") == 0) { emit(0x0F); emit(0x85); } // JNE
                else if (sys_strcmp(op1, "!=") == 0) { emit(0x0F); emit(0x84); } // JE
                else if (sys_strcmp(op1, "<") == 0) { emit(0x0F); emit(0x8D); } // JGE
                else if (sys_strcmp(op1, ">") == 0) { emit(0x0F); emit(0x8E); } // JLE
                else if (sys_strcmp(op1, "<=") == 0) { emit(0x0F); emit(0x8F); } // JG
                else if (sys_strcmp(op1, ">=") == 0) { emit(0x0F); emit(0x8C); } // JL
                
                int p1 = code_pos;
                emit32(-1); // End of chain

                // Check 2
                if (isdigit(v4[0]) || (v4[0] == '-' && isdigit(v4[1])) || v4[0] == '\'') {
                    int val2 = 0;
                    if (v4[0] == '\'') {
                        if (v4[1] == '\\') {
                            if (v4[2] == 't') val2 = '\t';
                            else if (v4[2] == 'n') val2 = '\n';
                            else if (v4[2] == 'r') val2 = '\r';
                            else if (v4[2] == '0') val2 = 0;
                            else val2 = v4[2];
                        } else val2 = v4[1];
                    } else val2 = parse_int(v4);
                    emit_cmp_mem_imm(off2, val2);
                } else {
                    int off_v4 = get_var_offset(v4);
                    emit_load(off2);
                    emit_cmp_eax_mem(off_v4);
                }

                // Jump if FALSE
                if (sys_strcmp(op2, "==") == 0) { emit(0x0F); emit(0x85); } // JNE
                else if (sys_strcmp(op2, "!=") == 0) { emit(0x0F); emit(0x84); } // JE
                else if (sys_strcmp(op2, "<") == 0) { emit(0x0F); emit(0x8D); } // JGE
                else if (sys_strcmp(op2, ">") == 0) { emit(0x0F); emit(0x8E); } // JLE
                else if (sys_strcmp(op2, "<=") == 0) { emit(0x0F); emit(0x8F); } // JG
                else if (sys_strcmp(op2, ">=") == 0) { emit(0x0F); emit(0x8C); } // JL
                
                int p2 = code_pos;
                emit32(p1); // Link p2 -> p1
                patch_pos = p2;

            } else if (sys_strcmp(log, "||") == 0) {
                // OR: One must be true. If first is true, jump to BODY.
                
                // Jump if TRUE
                if (sys_strcmp(op1, "==") == 0) { emit(0x0F); emit(0x84); } // JE
                else if (sys_strcmp(op1, "!=") == 0) { emit(0x0F); emit(0x85); } // JNE
                else if (sys_strcmp(op1, "<") == 0) { emit(0x0F); emit(0x8C); } // JL
                else if (sys_strcmp(op1, ">") == 0) { emit(0x0F); emit(0x8F); } // JG
                else if (sys_strcmp(op1, "<=") == 0) { emit(0x0F); emit(0x8E); } // JLE
                else if (sys_strcmp(op1, ">=") == 0) { emit(0x0F); emit(0x8D); } // JGE
                
                int jump_body = code_pos;
                emit32(0); // Placeholder

                // Check 2
                if (isdigit(v4[0]) || (v4[0] == '-' && isdigit(v4[1])) || v4[0] == '\'') {
                    int val2 = 0;
                    if (v4[0] == '\'') {
                        if (v4[1] == '\\') {
                            if (v4[2] == 't') val2 = '\t';
                            else if (v4[2] == 'n') val2 = '\n';
                            else if (v4[2] == 'r') val2 = '\r';
                            else if (v4[2] == '0') val2 = 0;
                            else val2 = v4[2];
                        } else val2 = v4[1];
                    } else val2 = parse_int(v4);
                    emit_cmp_mem_imm(off2, val2);
                } else {
                    int off_v4 = get_var_offset(v4);
                    emit_load(off2);
                    emit_cmp_eax_mem(off_v4);
                }

                // Jump if FALSE (to END)
                if (sys_strcmp(op2, "==") == 0) { emit(0x0F); emit(0x85); } // JNE
                else if (sys_strcmp(op2, "!=") == 0) { emit(0x0F); emit(0x84); } // JE
                else if (sys_strcmp(op2, "<") == 0) { emit(0x0F); emit(0x8D); } // JGE
                else if (sys_strcmp(op2, ">") == 0) { emit(0x0F); emit(0x8E); } // JLE
                else if (sys_strcmp(op2, "<=") == 0) { emit(0x0F); emit(0x8F); } // JG
                else if (sys_strcmp(op2, ">=") == 0) { emit(0x0F); emit(0x8C); } // JL
                
                patch_pos = code_pos;
                emit32(-1);

                // Patch jump_body to here (start of block)
                int rel = code_pos - (jump_body + 4);
                code[jump_body] = rel & 0xFF; code[jump_body+1] = (rel >> 8) & 0xFF; code[jump_body+2] = (rel >> 16) & 0xFF; code[jump_body+3] = (rel >> 24) & 0xFF;
            }

            push_block(0, patch_pos, 0);
        }
        // 5f. String Compare: if (strcmp(a, b) == 0)
        else if (sscanf(line, " if ( strcmp ( %127[^,], %127[^)] ) == 0 ) {", v1, v2) == 2) {
            strip(v1); strip(v2);
            
            // Load v1 into ESI
            if (v1[0] == '"') {
                char *s = v1 + 1; s[strlen(s)-1] = 0; // Strip quotes
                int len = strlen(s);
                emit(0xE9); emit32(len+1);
                uint32_t addr = 0x08048000 + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + code_pos;
                for(int i=0; i<len; i++) emit(s[i]);
                emit(0);
                emit(0xBE); emit32(addr); // MOV ESI, addr
            } else {
                int off = get_var_offset(v1);
                emit_load(off);
                emit(0x89); emit(0xC6); // MOV ESI, EAX
            }

            // Load v2 into EDI
            if (v2[0] == '"') {
                char *s = v2 + 1; s[strlen(s)-1] = 0;
                int len = strlen(s);
                emit(0xE9); emit32(len+1);
                uint32_t addr = 0x08048000 + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + code_pos;
                for(int i=0; i<len; i++) emit(s[i]);
                emit(0);
                emit(0xBF); emit32(addr); // MOV EDI, addr
            } else {
                int off = get_var_offset(v2);
                emit_load(off);
                emit(0x89); emit(0xC7); // MOV EDI, EAX
            }
            
            // Inline strcmp loop (ESI, EDI -> EAX)
            emit(0x31); emit(0xC0); // xor eax, eax
            int loop_start = code_pos;
            
            emit(0x8A); emit(0x1F); // mov bl, [edi]
            emit(0x38); emit(0x1E); // cmp [esi], bl
            emit(0x75); emit(0x09); // jne .diff (+9)
            
            emit(0x80); emit(0x3E); emit(0x00); // cmp byte [esi], 0
            emit(0x74); emit(0x0B); // je .equal (+11)
            
            emit(0x46); emit(0x47); // inc esi, inc edi
            emit(0xEB); emit(loop_start - (code_pos + 1)); // jmp loop
            
            // .diff:
            emit(0xB8); emit32(1); // mov eax, 1
            emit(0xEB); emit(0x02); // jmp .end
            
            // .equal:
            emit(0x31); emit(0xC0); // xor eax, eax
            
            // .end: test eax, eax; jne <patch>
            emit(0x85); emit(0xC0); emit(0x0F); emit(0x85);
            int patch_pos = code_pos; emit32(-1);
            push_block(0, patch_pos, 0);
        }
        // 5. Generic If: if ( a > 10 ) { OR if ( a > b ) {
        else if (sscanf(line, " if ( %127s %31s %127[^)] )", v1, op1, v2) == 3 && sys_strstr(line, "{")) {
            strip(v1); strip(op1); strip(v2);
            int off1 = get_var_offset(v1);
            
            // Check if v2 is number, char literal or var
            if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1])) || v2[0] == '\'') {
                int val = 0;
                if (v2[0] == '\'') {
                    if (v2[1] == '\\') {
                        if (v2[2] == 't') val = '\t';
                        else if (v2[2] == 'n') val = '\n';
                        else if (v2[2] == 'r') val = '\r';
                        else if (v2[2] == '0') val = 0;
                        else val = v2[2];
                    } else val = v2[1];
                } else val = parse_int(v2);
                emit_cmp_mem_imm(off1, val);
            } else {
                int off2 = get_var_offset(v2);
                emit_load(off1);
                emit_cmp_eax_mem(off2);
            }
            
            // Emit Jump (Inverted Logic to skip block)
            emit(0x0F);
            if (sys_strcmp(op1, "==") == 0) emit(0x85);
            else if (sys_strcmp(op1, "!=") == 0) emit(0x84);
            else if (sys_strcmp(op1, "<") == 0) emit(0x8D);
            else if (sys_strcmp(op1, ">") == 0) emit(0x8E);
            else if (sys_strcmp(op1, "<=") == 0) emit(0x8F);
            else if (sys_strcmp(op1, ">=") == 0) emit(0x8C);
            else { print("Error on line "); print(current_line); print(": Unknown operator '"); print(op1); print("'\n"); exit(1); }

            int patch_pos = code_pos;
            emit32(-1); // Placeholder (4 bytes) - End of chain
            push_block(0, patch_pos, 0); // 0 = IF

            // Handle one-liner: if (...) { stmt; }
            char* brace = sys_strstr(line, "{");
            if (brace && *(brace + 1)) {
                char stmt[4096];
                sys_strcpy(stmt, brace + 1);
                char* close = sys_strrchr(stmt, '}');
                int has_close = 0;
                if (close) { *close = 0; has_close = 1; }
                compile_line(stmt);
                if (has_close) compile_line("}");
            }
        }
        // 7. Generic While: while ( a < 10 ) {
        else if (sscanf(line, " while ( %127s %31s %127[^)] )", v1, op1, v2) == 3 && sys_strstr(line, "{")) {
            strip(v1); strip(op1); strip(v2);
            int off = get_var_offset(v1);
            int start_pos = code_pos; // Loop start merken
            
            // Check if v2 is number, char literal or var
            if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1])) || v2[0] == '\'') {
                int val = 0;
                if (v2[0] == '\'') {
                    if (v2[1] == '\\') {
                        if (v2[2] == 't') val = '\t';
                        else if (v2[2] == 'n') val = '\n';
                        else if (v2[2] == 'r') val = '\r';
                        else if (v2[2] == '0') val = 0;
                        else val = v2[2];
                    } else val = v2[1];
                } else val = parse_int(v2);
                emit_cmp_mem_imm(off, val);
            } else {
                int off2 = get_var_offset(v2);
                emit_load(off);
                emit_cmp_eax_mem(off2);
            }
            
            // Emit Jump (Inverted)
            emit(0x0F);
            if (sys_strcmp(op1, "==") == 0) emit(0x85);
            else if (sys_strcmp(op1, "!=") == 0) emit(0x84);
            else if (sys_strcmp(op1, "<") == 0) emit(0x8D);
            else if (sys_strcmp(op1, ">") == 0) emit(0x8E);
            else if (sys_strcmp(op1, "<=") == 0) emit(0x8F);
            else if (sys_strcmp(op1, ">=") == 0) emit(0x8C);
            else { print("Error on line "); print(current_line); print(": Unknown operator '"); print(op1); print("'\n"); exit(1); }

            int patch_pos = code_pos;
            emit32(-1);
            push_block(1, patch_pos, start_pos); // 1 = WHILE

            // Handle one-liner
            char* brace = sys_strstr(line, "{");
            if (brace && *(brace + 1)) {
                char stmt[4096];
                sys_strcpy(stmt, brace + 1);
                char* close = sys_strrchr(stmt, '}');
                int has_close = 0;
                if (close) { *close = 0; has_close = 1; }
                compile_line(stmt);
                if (has_close) compile_line("}");
            }
        }
        // 12. For Loop: for (init; cond; inc) {
        else if (sscanf(line, " for ( %127[^;]; %127[^;]; %1023[^)] )", v1, v2, str_buf) == 3 && sys_strstr(line, "{")) {
            // 1. Init: v1 (z.B. "i=0") -> "i=0;"
            snprintf(init_stmt, 256, "%s;", v1); // sizeof replaced
            compile_line(init_stmt); // Rekursiver Aufruf für Init

            int start_pos = code_pos; // Loop start

            // 2. Condition: v2 (z.B. "i < 10")
            char cond_var[32];
            char cond_limit[32];
            if (sscanf(v2, " %31[^ <] < %31s", cond_var, cond_limit) == 2) {
                strip(cond_var);
                strip(cond_limit);
                int off = get_var_offset(cond_var);
                
                if (isdigit(cond_limit[0]) || (cond_limit[0] == '-' && isdigit(cond_limit[1]))) {
                    emit_cmp_mem_imm(off, parse_int(cond_limit));
                } else {
                    int limit_off = get_var_offset(cond_limit);
                    emit_load(off);
                    emit_cmp_eax_mem(limit_off);
                }
                emit(0x0F); emit(0x8D); // jge (exit)
                int patch_pos = code_pos;
                emit32(-1);
                
                push_block(3, patch_pos, start_pos); // 3 = FOR
                snprintf(block_stack[block_stack_idx-1].for_inc, 2048, "%s;", str_buf); // sizeof replaced

                // Handle one-liner
                char* brace = sys_strstr(line, "{");
                if (brace && *(brace + 1)) {
                    char stmt[4096];
                    sys_strcpy(stmt, brace + 1);
                    char* close = sys_strrchr(stmt, '}');
                    int has_close = 0;
                    if (close) { *close = 0; has_close = 1; }
                    compile_line(stmt);
                    if (has_close) compile_line("}");
                }
            } else {
                print("Error on line "); print(current_line); print(": Invalid for-loop condition\n");
            }
        }
        // 16. Switch: switch (var) {
        else if (sscanf(line, " switch ( %127[^ )] ) {", v1) == 1) {
            strip(v1);
            int off = get_var_offset(v1);
            
            // Emit JMP to dispatch (placeholder) - we jump over the cases first
            emit(0xE9);
            int patch_pos = code_pos;
            emit32(-1);
            
            push_block(5, -1, 0); // 5 = SWITCH
            block_stack[block_stack_idx-1].switch_var_offset = off;
            block_stack[block_stack_idx-1].dispatch_jump_pos = patch_pos;
        }
        // 17. Case: case 10:
        else if (sscanf(line, " case %d:", &val) == 1) {
            int i = block_stack_idx - 1;
            if (i >= 0 && block_stack[i].type == 5) {
                block_stack[i].case_values[block_stack[i].case_count] = val;
                block_stack[i].case_offsets[block_stack[i].case_count] = code_pos;
                block_stack[i].case_count++;
            } else {
                print("Error on line "); print(current_line); print(": 'case' outside of switch\n");
            }
        }
        // 18. Default: default:
        else if (find_code(line, "default:")) {
            int i = block_stack_idx - 1;
            if (i >= 0 && block_stack[i].type == 5) {
                block_stack[i].default_offset = code_pos;
            }
        }
        // 13. Do-While: do {
        else if (find_code(line, "do {")) {
            int start_pos = code_pos;
            push_block(4, -1, start_pos); // 4 = DO_WHILE
        }
        // 13b. End Do-While: } while (a < 10);
        else if (sys_strstr(line, "} while (") && sscanf(line, " } while ( %127s %31s %127[^)] );", v1, op1, v2) == 3) {
            Block b = pop_block();
            if (b.type == 4) { // DO_WHILE
                // 1. Resolve 'continue' jumps to here (start of condition)
                int current_cont = b.continue_head;
                while (current_cont != -1) {
                    int next_cont = code[current_cont] | (code[current_cont+1] << 8) | (code[current_cont+2] << 16) | (code[current_cont+3] << 24);
                    int rel_cont = code_pos - (current_cont + 4);
                    code[current_cont] = rel_cont & 0xFF;
                    code[current_cont+1] = (rel_cont >> 8) & 0xFF;
                    code[current_cont+2] = (rel_cont >> 16) & 0xFF;
                    code[current_cont+3] = (rel_cont >> 24) & 0xFF;
                    current_cont = next_cont;
                }

                // 2. Emit Condition Code (Same as Generic If/While but jump back if TRUE)
                strip(v1); strip(op1); strip(v2);
                int off1 = get_var_offset(v1);
                
                if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1])) || v2[0] == '\'') {
                    int val = 0;
                    if (v2[0] == '\'') {
                        if (v2[1] == '\\') {
                            if (v2[2] == 't') val = '\t';
                            else if (v2[2] == 'n') val = '\n';
                            else if (v2[2] == 'r') val = '\r';
                            else if (v2[2] == '0') val = 0;
                            else val = v2[2];
                        } else val = v2[1];
                    } else val = parse_int(v2);
                    emit_cmp_mem_imm(off1, val);
                } else {
                    int off2 = get_var_offset(v2);
                    emit_load(off1);
                    emit_cmp_eax_mem(off2);
                }
                
                // 3. Jump back to start if TRUE
                emit(0x0F);
                if (sys_strcmp(op1, "==") == 0) emit(0x84);
                else if (sys_strcmp(op1, "!=") == 0) emit(0x85);
                else if (sys_strcmp(op1, "<") == 0) emit(0x8C);
                else if (sys_strcmp(op1, ">") == 0) emit(0x8F);
                else if (sys_strcmp(op1, "<=") == 0) emit(0x8E);
                else if (sys_strcmp(op1, ">=") == 0) emit(0x8D);
                
                int rel = b.start_pos - (code_pos + 4);
                emit32(rel);

                // 4. Resolve breaks (target = current code_pos, after loop)
                resolve_patch_chain(b.break_head, code_pos);
            }
        }
        // 10. Break: break;
        else if (sys_strstr(line, "break;")) {
            // Finde die innerste Schleife im Stack
            int i;
            for (i = block_stack_idx - 1; i >= 0; i--) {
                if (block_stack[i].type == 1 || block_stack[i].type == 3 || block_stack[i].type == 5) break;
            }
            if (i >= 0) {
                // JMP <placeholder> (Unconditional Jump) -> E9 <rel32>
                emit(0xE9);
                int patch_pos = code_pos;
                emit32(block_stack[i].break_head); // Speichere vorherigen Head im Code (Linked List)
                block_stack[i].break_head = patch_pos; // Update Head
            } else {
                print("Error on line "); print(current_line); print(": 'break' outside of loop\n");
            }
        }
        // 11. Continue: continue;
        else if (sys_strstr(line, "continue;")) {
            // Finde die innerste Schleife im Stack
            int i;
            for (i = block_stack_idx - 1; i >= 0; i--) {
                if (block_stack[i].type == 1 || block_stack[i].type == 3 || block_stack[i].type == 4) break;
            }
            if (i >= 0) {
                // JMP <rel32>
                emit(0xE9);
                if (block_stack[i].type == 1) { // WHILE: Jump to start
                    int rel = block_stack[i].start_pos - (code_pos + 4);
                    emit32(rel);
                } else if (block_stack[i].type == 3 || block_stack[i].type == 4) { // FOR or DO_WHILE (Jump to condition check)
                    int patch_pos = code_pos;
                    emit32(block_stack[i].continue_head);
                    block_stack[i].continue_head = patch_pos;
                }
            } else {
                print("Error on line "); print(current_line); print(": 'continue' outside of loop\n");
            }
        }
        // 8a. Print String: print("Hello");
        else if (sscanf(line, " print ( \"%1023[^\"]\" );", str_buf) == 1) {
            // Escape-Sequenzen behandeln (\n -> Byte 10)
            char parsed_str[128];
            int len = 0;
            for (int i = 0; str_buf[i]; i++) {
                if (str_buf[i] == '\\' && str_buf[i+1] == 'n') {
                    parsed_str[len++] = '\n';
                    i++;
                } else {
                    parsed_str[len++] = str_buf[i];
                }
            }
            
            // 1. Jump over data (E9 <rel32>)
            emit(0xE9); emit32(len);
            
            // 2. String Data Address berechnen
            // Base (0x08048000) + Headers (84) + Current Code Pos
            uint32_t string_addr = 0x08048000 + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + code_pos;
            
            // 3. Emit String Data
            for (int i = 0; i < len; i++) emit(parsed_str[i]);
            
            // 4. Syscall write(1, string_addr, len)
            // mov ecx, string_addr
            emit(0xB9); emit32(string_addr);
            // mov edx, len
            emit(0xBA); emit32(len);
            // mov ebx, 1 (stdout); mov eax, 4 (write); int 0x80
            emit(0xBB); emit32(1); emit(0xB8); emit32(4); emit(0xCD); emit(0x80);
        }
        // 8b. Print Function Call: print(sum(a,b));
        else if (sys_strstr(line, "print") && sys_strstr(line, "(") && sys_strstr(line, "))") && sscanf(line, " print ( %127[^(](%1023[^)]) );", v1, str_buf) >= 1) {
            strip(v1);
            int idx = get_function_index(v1);
            
            // Parse Args & Push (Reverse Order)
            int arg_count = 0;
            if (str_buf[0]) {
                char* arg_ptrs[32];
                arg_count = parse_arguments(str_buf, arg_ptrs, 32);
                
                for (int i = arg_count - 1; i >= 0; i--) {
                    char* arg = arg_ptrs[i];
                    if (isdigit(arg[0]) || (arg[0] == '-' && isdigit(arg[1]))) {
                        int val = parse_int(arg);
                        if (g_debuglevel) { print("// Pushing imm32: "); print(val); }
                        if (val >= -128 && val <= 127) { emit(0x6A); emit(val & 0xFF); }
                        else { emit(0x68); emit32(val); }
                    } else {
                        int off = get_var_offset(arg);
                        if (g_debuglevel) { print("// Pushing var from offset: "); print(off); }
                        if (off >= -128 && off <= 127) { emit(0xFF); emit(0x75); emit((uint8_t)off); }
                        else { emit(0xFF); emit(0xB5); emit32(off); } // PUSH [EBP+off32]
                    }
                }
            }
            emit(0xE8); // CALL
            if (functions[idx].address != -1) { emit32(functions[idx].address - (code_pos + 4)); }
            else { int patch = code_pos; emit32(functions[idx].patch_head); functions[idx].patch_head = patch; }
            if (arg_count > 0) { emit(0x83); emit(0xC4); emit(arg_count * 4); }
            
            emit_print_eax();
        }
        // 8. Print: print(var);
        else if (sscanf(line, " print ( %127[^ )] );", v1) == 1) {
            strip(v1);
            int off = get_var_offset(v1);
            emit_load(off);
            emit_print_eax();
        }
        // 15. Function Call: func(); (Verschoben nach unten, damit print nicht gefressen wird)
        else if (sys_strstr(line, "(") && sys_strstr(line, ");") && sscanf(line, " %127[^(](%1023[^)])", v1, str_buf) >= 1) {
            strip(v1);
            // Filter keywords that look like calls
            if (sys_strcmp(v1, "print") != 0 && sys_strcmp(v1, "return") != 0 && sys_strcmp(v1, "break") != 0 && sys_strcmp(v1, "continue") != 0 && sys_strcmp(v1, "while") != 0 && sys_strcmp(v1, "if") != 0 && sys_strcmp(v1, "switch") != 0) {
                int idx = get_function_index(v1);
                
                // Parse Args & Push (Reverse Order)
                int arg_count = 0;
                if (str_buf[0]) {
                    char* arg_ptrs[32];
                    arg_count = parse_arguments(str_buf, arg_ptrs, 32);
                    
                    for (int i = arg_count - 1; i >= 0; i--) {
                        char* arg = arg_ptrs[i];
                        if (isdigit(arg[0]) || (arg[0] == '-' && isdigit(arg[1]))) {
                            int val = parse_int(arg);
                            if (g_debuglevel) { print("// Pushing imm32: "); print(val); }
                            if (val >= -128 && val <= 127) { emit(0x6A); emit(val & 0xFF); } // push byte
                            else { emit(0x68); emit32(val); } // push imm32
                        } else {
                            int off = get_var_offset(arg);
                            if (g_debuglevel) { print("// Pushing var from offset: "); print(off); }
                            if (off > 10000) { emit(0xFF); emit(0x35); emit32(off); } // push [addr]
                            else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x75); emit((uint8_t)off); } // push [ebp+off8]
                            else { emit(0xFF); emit(0xB5); emit32(off); } // push [ebp+off32]
                        }
                    }
                }

                emit(0xE8); // CALL rel32
                if (functions[idx].address != -1) {
                    emit32(functions[idx].address - (code_pos + 4));
                } else {
                    int patch = code_pos;
                    emit32(functions[idx].patch_head);
                    functions[idx].patch_head = patch;
                }
                // Stack cleanup (cdecl): add esp, arg_count * 4
                if (arg_count > 0) { emit(0x83); emit(0xC4); emit(arg_count * 4); }
            }
        }
        // 6. Return Expression: return a + b;
        else if (sscanf(line, " return %127[^ +] + %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int off1 = get_var_offset(v1);
            int off2 = get_var_offset(v2);
            
            emit_load(off1);
            emit_op_eax_mem(0x03, off2); // ADD
            
            emit_return();
        }
        // 6b. Return Subtraction: return a - b;
        else if (sscanf(line, " return %127[^ -] - %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int off1 = get_var_offset(v1);
            int off2 = get_var_offset(v2);
            
            emit_load(off1);
            emit_op_eax_mem(0x2B, off2); // SUB
            
            emit_return();
        }
        // 6c. Return Multiplication: return a * b;
        else if (sscanf(line, " return %127[^ *] * %127[^;];", v1, v2) == 2) {
            strip(v1); strip(v2);
            int off1 = get_var_offset(v1);
            int off2 = get_var_offset(v2);
            
            emit_load(off1);
            // IMUL EAX, r/m32
            if (off2 > 10000) { 
                emit(0x0F); emit(0xAF); emit(0x05); emit32(off2); 
            } else { 
                if (off2 >= -128 && off2 <= 127) {
                    emit(0x0F); emit(0xAF); emit(0x45); emit((uint8_t)off2);
                } else {
                    emit(0x0F); emit(0xAF); emit(0x85); emit32(off2);
                }
            }
            
            emit_return();
        }
        // 4a. Return Constant: return 0;
        else if (sscanf(line, " return %d ;", &val) == 1) { // Added space to handle "return 0;" vs "return 0 ;"
            // mov eax, val
            emit(0xB8); emit32(val);
            emit_return();
        }
        // 4b. Return Void: return;
        else if (sys_strstr(line, "return;")) {
            emit_return();
        }
        // 4. Return: return a;
        else if (sscanf(line, " return %127[^;];", v1) == 1) {
            strip(v1);
            
            // Check if it's a constant number (fallback if 4a failed due to parsing)
            if (isdigit(v1[0]) || (v1[0] == '-' && isdigit(v1[1]))) {
                 int val = parse_int(v1);
                 emit(0xB8); emit32(val);
                 emit_return();
                 return;
            }

            // Check for Array Return: return arr[i];
            char arr_name[64], idx_name[64];
            if (sscanf(v1, " %63[^ [ ] [ %63[^]] ]", arr_name, idx_name) == 2) {
                strip(arr_name); strip(idx_name);
                
                // Handle Side Effects in Index
                int post_inc = 0, pre_dec = 0;
                if (sys_strstr(idx_name, "++")) {
                    char* p = sys_strstr(idx_name, "++"); *p = 0; strip(idx_name); post_inc = 1;
                } else if (idx_name[0] == '-' && idx_name[1] == '-') {
                    memmove(idx_name, idx_name+2, strlen(idx_name)); strip(idx_name); pre_dec = 1;
                }

                if (pre_dec) {
                    int off = get_var_offset(idx_name);
                    if (off > 10000) { emit(0xFF); emit(0x0D); emit32(off); }
                    else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x4D); emit((uint8_t)off); }
                    else { emit(0xFF); emit(0x8D); emit32(off); }
                }

                int arr_off = get_var_offset(arr_name);
                int type = get_var_type(arr_name);
                if (type >= 200) emit_load(arr_off); else emit_lea(arr_off);
                emit(0x89); emit(0xC3); // MOV EBX, EAX

                int idx_off = get_var_offset(idx_name);
                emit_load(idx_off);
                emit(0x89); emit(0xC1); // MOV ECX, EAX
                
                if (type == 1 || type == 2) { emit(0x8A); emit(0x04); emit(0x0B); emit(0x25); emit32(0xFF); } // Byte
                else { emit(0x8B); emit(0x04); emit(0x8B); } // Int

                if (post_inc) {
                    // Save EAX (result) before INC
                    emit(0x50); 
                    int off = get_var_offset(idx_name);
                    if (off > 10000) { emit(0xFF); emit(0x05); emit32(off); }
                    else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x45); emit((uint8_t)off); }
                    else { emit(0xFF); emit(0x85); emit32(off); }
                    emit(0x58); // Restore EAX
                }
                emit_return();
            } else {
                // Normal Variable Return: return var; OR return var++;
                int post_inc = 0;
                if (sys_strstr(v1, "++")) {
                    char* p = sys_strstr(v1, "++"); *p = 0; strip(v1); post_inc = 1;
                }
                
                int off = get_var_offset(v1);
                emit_load(off);
                
                if (post_inc) {
                    // Save EAX, INC var, Restore EAX
                    emit(0x50);
                    if (off > 10000) { emit(0xFF); emit(0x05); emit32(off); }
                    else if (off >= -128 && off <= 127) { emit(0xFF); emit(0x45); emit((uint8_t)off); }
                    else { emit(0xFF); emit(0x85); emit32(off); }
                    emit(0x58);
                }
                
                emit_return();
            }
        }
        // 9b. Else If: } else if ( ... ) {
        else if (sys_strstr(line, "} else if (") && sscanf(line, " } else if ( %127s %31s %127[^)] )", v1, op1, v2) == 3 && sys_strstr(line, "{")) {
             Block b = pop_block();
             if (b.type == 0) { // IF
                 // 1. Emit JMP over rest of chain (Success of previous block)
                 emit(0xE9);
                 emit32(b.else_chain_head); // Link to previous chain
                 int new_head = code_pos - 4;
                 
                 // 2. Patch previous failure to here
                 resolve_patch_chain(b.patch_pos, code_pos);
                 
                 // 3. Parse Condition (Copy-Paste from Generic If)
                 strip(v1); strip(op1); strip(v2);
                 int off1 = get_var_offset(v1);
                 if (isdigit(v2[0]) || (v2[0] == '-' && isdigit(v2[1])) || v2[0] == '\'') {
                     int val = 0;
                     if (v2[0] == '\'') {
                         if (v2[1] == '\\') {
                             if (v2[2] == 't') val = '\t';
                             else if (v2[2] == 'n') val = '\n';
                             else if (v2[2] == 'r') val = '\r';
                             else if (v2[2] == '0') val = 0;
                             else val = v2[2];
                         } else val = v2[1];
                     } else val = parse_int(v2);
                     emit_cmp_mem_imm(off1, val);
                 } else {
                     int off2 = get_var_offset(v2);
                     emit_load(off1);
                     emit_cmp_eax_mem(off2);
                 }
                 
                 // 4. Emit JNE/etc (Failure of this block)
                 emit(0x0F);
                 if (sys_strcmp(op1, "==") == 0) emit(0x85);
                 else if (sys_strcmp(op1, "!=") == 0) emit(0x84);
                 else if (sys_strcmp(op1, "<") == 0) emit(0x8D);
                 else if (sys_strcmp(op1, ">") == 0) emit(0x8E);
                 else if (sys_strcmp(op1, "<=") == 0) emit(0x8F);
                 else if (sys_strcmp(op1, ">=") == 0) emit(0x8C);
                 
                 int patch_pos = code_pos;
                 emit32(-1);
                 
                 push_block(0, patch_pos, 0); // Type 0 (IF)
                 block_stack[block_stack_idx-1].else_chain_head = new_head;

                 // Handle one-liner
                 char* brace = sys_strstr(line, "{");
                 if (brace && *(brace + 1)) {
                     char stmt[4096];
                     sys_strcpy(stmt, brace + 1);
                     char* close = sys_strrchr(stmt, '}');
                     int has_close = 0;
                     if (close) { *close = 0; has_close = 1; }
                     compile_line(stmt);
                     if (has_close) compile_line("}");
                 }
             }
        }
        // 9. Else: } else {
        else if (find_code(line, "} else {")) {
            Block b = pop_block();
            if (b.type == 0) { // Must be IF
                // 1. Emit JMP over ELSE block
                emit(0xE9); // JMP rel32
                emit32(b.else_chain_head);
                int new_head = code_pos - 4;
                
                // 2. Backpatch IF failure to here (start of ELSE)
                resolve_patch_chain(b.patch_pos, code_pos);
                
                // 3. Push ELSE block
                push_block(2, -1, 0); // 2 = ELSE. patch_pos unused.
                block_stack[block_stack_idx-1].else_chain_head = new_head;

                // Handle one-liner
                char* brace = sys_strstr(line, "{");
                if (brace && *(brace + 1)) {
                    char stmt[4096];
                    sys_strcpy(stmt, brace + 1);
                    char* close = sys_strrchr(stmt, '}');
                    int has_close = 0;
                    if (close) { *close = 0; has_close = 1; }
                    compile_line(stmt);
                    if (has_close) compile_line("}");
                }
            }
        }
        else if (find_code(line, "}")) {
            // Backpatching für if/while
            Block b = pop_block();
            if (b.type != -1) {
                if (b.type == 0 || b.type == 2) { // IF or ELSE
                    resolve_patch_chain(b.patch_pos, code_pos);
                    resolve_patch_chain(b.else_chain_head, code_pos); // Resolve all success jumps
                } else if (b.type == 1) { // WHILE
                    // Am Ende des Blocks: Sprung zurück zum Start
                    emit(0xE9); // JMP rel32
                    int rel = b.start_pos - (code_pos + 4);
                    emit32(rel);
                    
                    // Resolve breaks (Backpatching Chain)
                    int current_break = b.break_head;
                    while (current_break != -1) {
                        // Nächsten Pointer aus dem Code lesen (da wir ihn dort gespeichert haben)
                        int next_break = code[current_break] | (code[current_break+1] << 8) | (code[current_break+2] << 16) | (code[current_break+3] << 24);
                        
                        // Patch JMP Ziel auf aktuelles code_pos (Ende der Schleife)
                        int rel_break = code_pos - (current_break + 4);
                        code[current_break] = rel_break & 0xFF;
                        code[current_break+1] = (rel_break >> 8) & 0xFF;
                        code[current_break+2] = (rel_break >> 16) & 0xFF;
                        code[current_break+3] = (rel_break >> 24) & 0xFF;
                        
                        current_break = next_break;
                    }
                    resolve_patch_chain(b.patch_pos, code_pos);
                } else if (b.type == 3) { // FOR
                    // 1. Resolve 'continue' jumps (target = start of increment)
                    int current_cont = b.continue_head;
                    while (current_cont != -1) {
                        int next_cont = code[current_cont] | (code[current_cont+1] << 8) | (code[current_cont+2] << 16) | (code[current_cont+3] << 24);
                        int rel_cont = code_pos - (current_cont + 4);
                        code[current_cont] = rel_cont & 0xFF;
                        code[current_cont+1] = (rel_cont >> 8) & 0xFF;
                        code[current_cont+2] = (rel_cont >> 16) & 0xFF;
                        code[current_cont+3] = (rel_cont >> 24) & 0xFF;
                        current_cont = next_cont;
                    }

                    // 2. Emit Increment Code
                    compile_line(b.for_inc);

                    // 3. Jump back to start (condition)
                    emit(0xE9);
                    int rel = b.start_pos - (code_pos + 4);
                    emit32(rel);

                    // 4. Resolve breaks (target = end of loop)
                    int current_break = b.break_head;
                    while (current_break != -1) {
                        int next_break = code[current_break] | (code[current_break+1] << 8) | (code[current_break+2] << 16) | (code[current_break+3] << 24);
                        int rel_break = code_pos - (current_break + 4);
                        code[current_break] = rel_break & 0xFF;
                        code[current_break+1] = (rel_break >> 8) & 0xFF;
                        code[current_break+2] = (rel_break >> 16) & 0xFF;
                        code[current_break+3] = (rel_break >> 24) & 0xFF;
                        current_break = next_break;
                    }
                    resolve_patch_chain(b.patch_pos, code_pos);
                } else if (b.type == 5) { // SWITCH
                    // 1. Resolve initial JMP to here (start of dispatch logic)
                    int rel = code_pos - (b.dispatch_jump_pos + 4);
                    code[b.dispatch_jump_pos] = rel & 0xFF;
                    code[b.dispatch_jump_pos+1] = (rel >> 8) & 0xFF;
                    code[b.dispatch_jump_pos+2] = (rel >> 16) & 0xFF;
                    code[b.dispatch_jump_pos+3] = (rel >> 24) & 0xFF;

                    // 2. Emit Dispatch Code (Compare and Jump back)
                    for (int i = 0; i < b.case_count; i++) {
                        // CMP [ebp-off], val
                        emit(0x81); emit(0x7D); emit((uint8_t)b.switch_var_offset); emit32(b.case_values[i]);
                        
                        // JE case_offset
                        emit(0x0F); emit(0x84);
                        int rel_case = b.case_offsets[i] - (code_pos + 4);
                        emit32(rel_case);
                    }

                    // 3. Default or Fallthrough
                    if (b.default_offset != -1) {
                        // JMP default_offset
                        emit(0xE9);
                        int rel_def = b.default_offset - (code_pos + 4);
                        emit32(rel_def);
                    }

                    // 4. Resolve breaks (target = current code_pos, which is AFTER dispatch)
                    resolve_patch_chain(b.break_head, code_pos);
                }
                
            } else if (!is_inside_main) {
                emit_return(); // Implicit return for void functions
                is_inside_func = 0;
            }
        }
        else if (line[0] != '\n' && line[0] != '/') {
            // Debugging: Zeige Zeilen, die nicht erkannt wurden
            // (Hilft zu verstehen, warum 0 Bytes generiert wurden)
            print("Warning: Skipped line: "); print(line);
        }
}

// --- Main Compiler Logic ---
int main(int argc, char** argv) {
    if (argc < 3) { print("Usage: ./compiler <source.c> <output.elf>\n"); return 1; }

    FILE* in = fopen(argv[1], "r");
    if (!in) { print("Error opening source\n"); return 1; }

    // Init dynamic arrays
    int max_vars; max_vars = 2000;
    symbols = sys_malloc(max_vars * sizeof(Symbol));
    functions = sys_malloc(max_vars * sizeof(Function));
    globals = sys_malloc(max_vars * sizeof(Global));
    block_stack = sys_malloc(max_vars * sizeof(Block));

    char line[4096];
    // Wir parsen Zeile für Zeile mit sscanf (Quick & Dirty)
    while(fgets(line, 4096, in)) { // sizeof replaced
        current_line++;
        compile_line(line);
    }
    fclose(in);

    if (main_addr == -1) {
        print("Error: 'main' function not found!\n");
        return 1;
    }

    // --- ELF Generierung ---
    // Base Address für Linux 32-bit Executables ist oft 0x08048000
    uint32_t base_addr = 0x08048000;
    uint32_t headers_size = 52 + 32; // sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr)
    uint32_t total_size = headers_size + code_pos;

    Elf32_Ehdr ehdr;
    int sz_ehdr;
    sz_ehdr = sizeof(Elf32_Ehdr);
    void *ptr_ehdr;
    ptr_ehdr = &ehdr;
    sys_memset(ptr_ehdr, 0, sz_ehdr);
    char* elf_magic = "\x7F\x45\x4C\x46\x01\x01\x01\x00";
    void *ptr_ident;
    ptr_ident = &ehdr.e_ident;
    sys_memcpy(ptr_ident, elf_magic, 8); // Magic, 32-bit, LSB, Ver 1
    ehdr.e_type = 2;      // Executable
    ehdr.e_machine = 3;   // i386
    ehdr.e_version = 1;
    ehdr.e_entry = base_addr + headers_size + main_addr; // Entry Point ist main()
    ehdr.e_phoff = 52;       // sizeof(Elf32_Ehdr)
    ehdr.e_ehsize = 52;
    ehdr.e_phentsize = 32;   // sizeof(Elf32_Phdr)
    ehdr.e_phnum = 1;     // Wir haben nur 1 Segment
    
    Elf32_Phdr phdr;
    int sz_phdr;
    sz_phdr = sizeof(Elf32_Phdr);
    void *ptr_phdr;
    ptr_phdr = &phdr;
    sys_memset(ptr_phdr, 0, sz_phdr);
    phdr.p_type = 1;      // LOAD
    phdr.p_offset = 0;    // Lade die ganze Datei
    phdr.p_vaddr = base_addr;
    phdr.p_paddr = base_addr;
    phdr.p_filesz = total_size;
    phdr.p_memsz = 0x80000; // 512KB Memory (Code + Globals)
    phdr.p_flags = 0x7;   // RWE (Read, Write, Execute) - Quick & Dirty: alles erlaubt
    phdr.p_align = 0x1000;
    
    FILE* out = fopen(argv[2], "wb");
    if (!out) { print("Error opening output file\n"); return 1; } // CRITICAL FIX
    sys_write(out, ptr_ehdr, 52);
    sys_write(out, ptr_phdr, 32);
    
    void* ptr_code;
    ptr_code = &code;
    sys_write(out, ptr_code, code_pos);
    
    fclose(out);
    
    print("Success! Wrote "); print(code_pos); print(" bytes code to "); print(argv[2]); print("\n");
    return 0;
}