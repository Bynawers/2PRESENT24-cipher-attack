#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "stdint.h"

/**
 * \details : cadencement de clé générant 11 sous clé à partir d'une clé maître
 * 
 * \param master_key : clé d'initialisation de 24 bits
 * \param k : 11 sous clés de 24 bits
 * \return : tableau de 11 sous clé K[i] de 24 bits
 */
void key_schedule(uint32_t master_key, uint32_t* k, int* S) {

    uint64_t master_higher_bits = ((uint64_t)master_key << 16);
    uint64_t master_lower_bits = 0x0;
    uint64_t tmp;

    for (int i = 0; i < 11; i++)  {

        k[i] = master_lower_bits >> 16;

        tmp = master_higher_bits;
        master_higher_bits = ((master_lower_bits & 0x7FFFF) << 21) ^ ((master_higher_bits) >> 19);
        master_lower_bits  = ((tmp & 0x7FFFF) << 21) ^ ((master_lower_bits) >> 19);

        tmp = master_higher_bits >> 36;
        master_higher_bits = master_higher_bits & 0x0FFFFFFFFF;
        master_higher_bits = master_higher_bits | ((uint64_t)S[tmp] << 36);

        master_lower_bits = master_lower_bits ^ (((uint64_t)i+1) << 15);
    }
}

/**
 * \details : subtitution bit à bit avec la boite S[i]
 * 
 * \param etat : registre de 24 bits
 * \return : message de 24 bits substitué
 */
uint32_t substitution(uint32_t etat, int* S) {

    uint32_t mask_delete[6] = {0x0FFFFF, 0xF0FFFF, 0xFF0FFF, 0xFFF0FF, 0xFFFF0F, 0xFFFFF0};
    uint32_t mask_keep[6] = {0xF, 0x0F, 0x00F, 0x000F, 0x0000F, 0x00000F};
    uint32_t shift = 24;
    uint32_t tmp;

    for (int i = 0; i < 6; i++) {
        shift -= 4;
        tmp = etat >> shift & mask_keep[i];
        etat = (etat & mask_delete[i]) | (S[tmp] << shift);
    }

    return etat;
}

/**
 * \details : permutation bit à bit avec le tableau P[i]
 * 
 * \param etat : registre de 24 bits
 * \return message de 24 bits permuté
 */
uint32_t permutation(uint32_t etat, int* P)  {

    uint64_t permutation = 0;

    for (int i = 0; i < 24; i++) {
        int distance = 23 - i;
        permutation = permutation | ((etat >> distance & 0x1) << (23 - P[i]));
    }
    return permutation;
}

/**
 * \details : chiffrement PRESENT24
 * 
 * \param message : registre de 24 bits
 * \param k : tableau de sous clé de 24 bits
 * \return message chiffré de 24 bits
 */
uint32_t encryption(uint32_t message, uint32_t* k) {

    int P[24] = { 0, 6, 12, 18, 1, 7, 13, 19, 2, 8, 14, 20, 3, 9, 15, 21, 4, 10, 16, 22, 5, 11, 17, 23 };
    int S[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

    uint32_t etat;
    uint32_t c;
    int i;

    etat = message;

    for (i = 0; i < 10; i++) {
        etat = etat ^ k[i];
        etat = substitution(etat, S);
        etat = permutation(etat, P);
    }
    etat = etat ^ k[i];

    c = etat;

    return c;
}