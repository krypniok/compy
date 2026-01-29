int g_var; // Global variable

typedef struct {
    int x;
    int y;
} Point;

int sum(int a, int b) {
    return a + b;
}

int fib(int n) {
    if (n < 2) {
        return n;
    }
    int a;
    int b;
    a = n - 1;
    b = n - 2;
    int f1;
    int f2;
    f1 = fib(a);
    f2 = fib(b);
    return f1 + f2;
}

void my_func() {
    print("Hello from my_func!\n");
}

void test_dynamic_arrays() {
    print("Testing Dynamic Arrays:\n");
    int dyn[5];
    int k = 2;
    dyn[k] = 99;
    int val_dyn;
    val_dyn = dyn[k];
    print(val_dyn);

    int j;
    int tmp;
    for (j = 0; j < 5; j = j + 1) {
        tmp = j + 10;
        dyn[j] = tmp;
    }
    val_dyn = dyn[3];
    print(val_dyn);
}

int main() {
    int a = 10;
    int b = 20;
    print("Start\n");
    
    if (a == 10) {
        print("a is 10\n");
        if (b == 20) {
            print("b is 20 (Nested)\n");
            if (a != b) {
                print("a != b (Deeply Nested)\n");
            }
        }
    }
    
    if (a == 5) {
        print("Should not print\n");
    } else {
        print("a is not 5\n");
        if (b == 20) {
            print("b is 20 in else\n");
        }
    }
    
    print("Testing break:\n");
    a = 0;
    while (a < 100) {
        a = a + 1;
        if (a == 5) {
            break;
        }
    }
    print(a); // Should be 5

    print("\nTesting continue (skip 5):\n");
    a = 0;
    while (a < 10) {
        a = a + 1;
        if (a == 5) {
            continue;
        }
        print(a);
    }
    print("\nDone\n");

    print("Testing for loop:\n");
    int i;
    for (i = 0; i < 5; i = i + 1) {
        print(i);
    }
    print("For loop done\n");

    print("Testing Logic:\n");
    a = 10;
    b = 20;
    if ( a == 10 && b == 20 ) {
        print("AND works\n");
    }
    if ( a == 5 || b == 20 ) {
        print("OR works\n");
    }

    print("Testing Switch:\n");
    a = 2;
    switch (a) {
        case 1:
            print("Case 1\n");
            break;
        case 2:
            print("Case 2 (Correct)\n");
            break;
        case 3:
            print("Case 3\n");
            break;
        default:
            print("Default\n");
    }

    print("Testing Pointers:\n");
    int *p;
    int x = 10;
    p = &x;
    *p = 20;
    print(x);
    int y;
    y = *p;
    print(y);

    print("Testing Arrays:\n");
    int arr[5];
    arr[0] = 100;
    arr[2] = 200;
    int z;
    z = arr[2];
    print(z);

    print("Testing Function Call:\n");
    my_func();

    print("Testing Params:\n");
    int res;
    res = sum(10, 20);
    print(res);
    res = sum(a, b);
    print(res);

    print("Testing Nested Print:\n");
    print(sum(100, 200));

    print("Testing Modulo:\n");
    int m;
    m = 10 % 3;
    print(m); // Expect 1

    print("Testing Recursion (Fib 10):\n");
    res = fib(10);
    print(res); // Expect 55

    print("Testing Comparisons:\n");
    int c = 10;
    if (c > 5) {
        print("10 > 5 (OK)\n");
    }
    if (c >= 10) {
        print("10 >= 10 (OK)\n");
    }
    if (c <= 10) {
        print("10 <= 10 (OK)\n");
    }
    if (c < 20) {
        print("10 < 20 (OK)\n");
    }
    
    // Test failure case (should not print)
    if (c > 20) {
        print("Error: 10 > 20\n");
    }
    
    print("Testing Else If:\n");
    int v = 20;
    if (v == 10) {
        print("v is 10\n");
    } else if (v == 20) {
        print("v is 20 (Correct)\n");
    } else {
        print("v is something else\n");
    }

    print("Testing Globals:\n");
    g_var = 77;
    print(g_var);
    g_var = g_var + 3;
    print(g_var); // Expect 80

    print("Testing Do-While:\n");
    int d = 0;
    do {
        d = d + 1;
        print(d);
    } while (d < 3);

    print("Testing Var Assignment & Chars:\n");
    int ch;
    ch = 'A';
    print(ch); // 65
    int ch2;
    ch2 = ch; // Var assignment
    ch2 = ch2 + 1;
    print(ch2); // 66 ('B')

    print("Testing Bitwise:\n");
    int b1 = 5;  // 101
    int b2 = 3;  // 011
    int b3;
    b3 = b1 & b2; // 1
    print(b3);
    b3 = b1 | b2; // 7
    print(b3);
    b3 = b1 ^ b2; // 6
    print(b3);

    print("Testing String Compare:\n");
    char *s1 = "hello";
    if (strcmp(s1, "hello") == 0) {
        print("s1 is hello\n");
    }
    if (strcmp(s1, "world") == 0) {
        print("s1 is world (Error)\n");
    } else {
        print("s1 is not world\n");
    }

    print("Testing Extensions:\n");
    int sh = 1;
    sh = sh << 3;
    print(sh); // 8
    sh = sh >> 1;
    print(sh); // 4
    
    int inc = 10;
    inc++;
    print(inc); // 11
    inc--;
    print(inc); // 10

    print("Testing Sizeof:\n");
    int sz;
    sz = sizeof(int);
    print(sz); // 4
    sz = sizeof(char);
    print(sz); // 1

    print("Testing Struct Pointers & Types:\n");
    uint32_t u32 = 12345;
    print(u32);
    uint8_t u8 = 255;
    print(u8);

    Point pt;
    pt.x = 111;
    pt.y = 222;
    Point *ppt;
    ppt = &pt;
    int pval;
    pval = ppt->x;
    print(pval); // 111
    ppt->y = 333;
    pval = ppt->y;
    print(pval); // 333

    test_dynamic_arrays();

    print("Back in main\n");
    return 0;
}
