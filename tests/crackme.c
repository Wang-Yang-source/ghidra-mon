/*
 * crackme.c - A simple reverse engineering challenge
 * Compile: gcc -o crackme crackme.c -no-pie
 * 
 * This binary implements a simple license key validation system.
 * The goal is to find the correct password through reverse engineering.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// XOR encryption key
static const char xor_key[] = "GhidraMon2024";

// Encrypted secret message (will be decrypted at runtime)
static const unsigned char encrypted_msg[] = {
    0x2a, 0x0d, 0x1a, 0x01, 0x09, 0x57, 0x3e, 0x41,
    0x25, 0x17, 0x00, 0x00
};

// Simple hash function
unsigned int simple_hash(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// XOR decrypt
void xor_decrypt(const unsigned char *input, char *output, int len) {
    int key_len = strlen(xor_key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ xor_key[i % key_len];
    }
    output[len] = '\0';
}

// Check license key
int check_license(const char *key) {
    // The correct key hashes to this value
    unsigned int target_hash = 0x7C9A1E3B;
    unsigned int key_hash = simple_hash(key);
    
    if (key_hash == target_hash) {
        return 1;
    }
    return 0;
}

// Validate password
int validate_password(const char *password) {
    // Password must be exactly 8 characters
    if (strlen(password) != 8) {
        return 0;
    }
    
    // Each character must satisfy certain conditions
    if (password[0] != 'R') return 0;
    if (password[1] != 'E') return 0;
    if (password[2] != 'V') return 0;
    if (password[3] != '3') return 0;
    if (password[4] != 'R') return 0;
    if (password[5] != 'S') return 0;
    if (password[6] != 'E') return 0;
    if (password[7] != '!') return 0;
    
    return 1;
}

// Print success banner
void print_banner(void) {
    printf("\n");
    printf("  ██████╗ ██╗  ██╗██╗██████╗ ██████╗  █████╗\n");
    printf(" ██╔════╝ ██║  ██║██║██╔══██╗██╔══██╗██╔══██╗\n");
    printf(" ██║  ███╗███████║██║██║  ██║██████╔╝███████║\n");
    printf(" ██║   ██║██╔══██║██║██║  ██║██╔══██╗██╔══██║\n");
    printf(" ╚██████╔╝██║  ██║██║██████╔╝██║  ██║██║  ██║\n");
    printf("  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n");
    printf("\n");
}

// Hidden function for secret feature
void secret_function(void) {
    char decrypted[32];
    xor_decrypt(encrypted_msg, decrypted, sizeof(encrypted_msg));
    printf("Secret: %s\n", decrypted);
}

int main(int argc, char *argv[]) {
    printf("=== CrackMe v1.0 - Ghidra-Mon Test Target ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        printf("Hint: The password is hidden in the binary.\n");
        return 1;
    }
    
    printf("Checking password: %s\n", argv[1]);
    
    if (validate_password(argv[1])) {
        print_banner();
        printf("✅ ACCESS GRANTED! Password is correct!\n\n");
        
        // Bonus: check for license key
        if (argc >= 3 && check_license(argv[2])) {
            secret_function();
        }
        return 0;
    } else {
        printf("❌ ACCESS DENIED! Wrong password.\n");
        return 1;
    }
}
