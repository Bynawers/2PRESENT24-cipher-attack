#include <stdio.h>
#include "stdint.h"

#include "encryption.h"

#include "decryption.h"

int main() {

    int S[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};
    int inv_S[16] = {5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10};

    uint32_t message;
    uint32_t message_test;
    uint32_t master_key;
    uint32_t k[11];
    uint32_t inv_k[11];

    uint32_t encrypted_message;
    uint32_t decrypted_message;

    message = 0x3af44f;
    message_test = 0x000000;
    master_key = 0x000000;

    printf("MASTER KEY = %#06x\n", master_key);
    printf("MESSAGE = %#06x\n", message_test);

    key_schedule(master_key, k, S);

    encrypted_message = encryption(message_test, k);
    
    printf("ENCRYPTED = %#06x\n", encrypted_message);

    key_schedule(master_key, inv_k, inv_S);

    decrypted_message = decryption(encrypted_message, k);

    printf("DECRYPTED = %#06x\n", decrypted_message);

    return 0;
}