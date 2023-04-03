#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "stdint.h"

#include "encryption.h"

#include "decryption.h"


void fusion(uint32_t **liste, uint32_t debut, uint32_t milieu, uint32_t fin)
{
    uint32_t i = debut;
    uint32_t j = milieu+1;
    uint32_t k = 0;

    uint32_t **tmp = malloc((fin-debut+1) * sizeof(uint32_t *));
    if (tmp == NULL) {
        fprintf(stderr, "Erreur d'allocation mémoire.\n");
        exit(EXIT_FAILURE);
    }

    while (i <= milieu && j <= fin) {
        if (liste[i][0] <= liste[j][0]) {
            tmp[k] = liste[i];
            i++;
        }
        else {
            tmp[k] = liste[j];
            j++;
        }
        k++;
    }

    if (i <= milieu) {
        while (i <= milieu) {
            tmp[k] = liste[i];
            i++;
            k++;
        }
    }
    else {
        while (j <= fin) {
            tmp[k] = liste[j];
            j++;
            k++;
        }
    }

    for (k = 0; k < fin-debut+1; k++) {
        liste[debut+k] = tmp[k];
    }

    free(tmp);
}

void tri_fusion(uint32_t **liste, uint32_t debut, uint32_t fin)
{
    if (debut < fin) {
        uint32_t milieu = (debut+fin)/2;
        tri_fusion(liste, debut, milieu);
        tri_fusion(liste, milieu+1, fin);
        fusion(liste, debut, milieu, fin);
    }
}

uint32_t** common_elements(uint32_t **lm, uint32_t **lc, uint32_t message_check, uint32_t cipher_check, uint32_t **keys) {

    uint32_t size = 16777216; // (2^56)

    uint32_t nb_keys = 0;
    uint32_t double_encryption_res = 0;

    uint32_t pivot = 0;
    uint32_t pivot_value = 0x000000;

    int i = 0;
    int j = 0;

    while (i < size && j < size) {
        
        if (lm[i][0] > lc[j][0]){
            j++;
        }
        else if (lm[i][0] < lc[j][0]){
            i++;
        }

        else {
            if (lm[i][0] != pivot_value) {
                pivot = j;
                pivot_value = lc[j][0];
            }

            double_encryption_res = double_encryption(message_check, lm[i][1], lc[j][1]);
            
            if (double_encryption_res == cipher_check) {

                keys = malloc((nb_keys+1) * sizeof(int*));
                keys[nb_keys] = malloc(2 * sizeof(uint32_t));

                keys[nb_keys][0] = lm[i][1];
                keys[nb_keys][1] = lc[j][1];

                printf("Trouvé ! %#06x %#06x \n", keys[nb_keys][0], keys[nb_keys][1]);

                nb_keys++;
            }

            if (i+1 >= size || j+1 >= size) {
                break;
            }

            if (lm[i][0] == lc[j+1][0]) {
                j++;
            }
            else {
                if (lm[i][0] == lm[i+1][0]) {
                    i++;
                    j = pivot;
                }
                else {
                    j++;
                    i++;
                }
            }
        }
    }
    return keys;
}

uint32_t attack(uint32_t clair, uint32_t chiffré, uint32_t clair2, uint32_t chiffré2) {

    uint32_t size = 16777216; // (2^56)
    uint32_t **lm = malloc(size * sizeof(int*));
    uint32_t **lc = malloc(size * sizeof(int*));
    
    uint32_t** keys =  malloc(sizeof(int*));
    uint32_t master_key;
    uint32_t k[11];
    uint32_t i;

    i = 0;

    printf("ALLOC\n");

    for (master_key = 0x0; master_key < size; master_key++) {

        key_schedule(master_key, k);

        lm[i] = malloc(2 * sizeof(uint32_t));
        lc[i] = malloc(2 * sizeof(uint32_t));

        
        lm[i][0] = encryption(clair, k);
        lc[i][0] = decryption(chiffré, k);

        lm[i][1] = master_key;
        lc[i][1] = master_key;

        i++;
    }

    printf("TRI FUSION\n");

    tri_fusion(lm, 0, size-1);
    tri_fusion(lc, 0, size-1);

    printf("COMMON\n");

    common_elements(lm, lc, clair2, chiffré2, keys);

    i = 0;

    while (keys[i] != NULL) {
        printf("k1 = %#06x k2 = %#06x\n", keys[i][0], keys[i][1]);
        i++;
    }

    printf("DESALLOC\n");

    for (uint32_t i = 0; i < size; i++) {
       
        free(lm[i]);
        free(lc[i]);
    }
    free(lm);
    free(lc);

    return 0;
};

// Etape 1: 2 Listes Lm Lc dans listes de tailles 2^56  (FAIT)
// Etapes 2: Pour chaque k: (k de 0 à 2^56)   (FAIT)
//             - Lm = DES(m)
//             - Lc = DES^-1(c) 
// Etapes 3: trier liste Lm et Lc pour trouver les éléments communs plus rapidement (tri fusion)
// Etapes 4: recherche les éléments égaux dans les 2 tableaux
// Etapes 5: tester plusieurs couples clair/chiffré pour vérifier la validité des clés
