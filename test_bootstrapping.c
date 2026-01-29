int main() {
    print("Testing File I/O Syscalls...\n");

    // 1. Open File (Read own source)
    int fd;
    char *filename = "test_bootstrapping.c";
    fd = fopen(filename, "r");
    
    if (fd < 0) {
        print("Error: Could not open file\n");
        exit(1);
    }
    print("File opened successfully. FD: ");
    print(fd);
    print("\n");

    // 2. Read Chars
    print("First 10 chars:\n");
    int i;
    int c;
    for (i = 0; i < 10; i = i + 1) {
        c = fgetc(fd);
        print(c); // Prints ASCII value
    }
    print("\n");

    // 3. Close
    fclose(fd);
    print("File closed.\n");
    return 0;
}