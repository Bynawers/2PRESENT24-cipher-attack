#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "stdint.h"

#include "encryption.h"

/**
 * \details : déchiffrement PRESENT24
 * 
 * \param message : registre de 24 bits
 * \param k : tableau de 11 sous clé de 24 bits
 * \return message déchiffré de 24 bits
 */
uint32_t decryption(uint32_t message, uint32_t* k) {

    int inv_P[24] = {0, 4, 8, 12, 16, 20, 1, 5, 9, 13, 17, 21, 2, 6, 10, 14, 18, 22, 3, 7, 11, 15, 19, 23};
    int inv_S[16] = {5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10};

    uint32_t etat;
    uint32_t c;

    etat = message;

    etat = etat ^ k[10];
    
    for (int i = 9; i > -1; i--) {
        etat = permutation(etat, inv_P);
        etat = substitution(etat, inv_S);

        etat = etat ^ k[i];
    }

    c = etat;

    return c;
}