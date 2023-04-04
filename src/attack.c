#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "stdint.h"

#include "encryption.h"
#include "decryption.h"

/**
 * \details : Fusion des listes
 * \param liste : Liste a trier
 * \param debut : Index de début de liste
 * \param milieu : Index de milieu de liste
 * \param fin : Index de fin de liste
 */
void merge(uint32_t **liste, uint32_t start, uint32_t middle, uint32_t end) {
    uint32_t i = start;
    uint32_t j = middle + 1;
    uint32_t k = 0;

    // Tableau utilisé pour stocker les éléments triés lors de la fusion
    uint32_t **tmp = malloc((end-start+1) * sizeof(uint32_t *));

    // Parcours les deux moitiés du tableau à fusionner,    
    // Compare les éléments et stock dans tmp dans l'ordre croissant 
    while (i <= middle && j <= end) {
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

    // Une fois que l'une des moitiés a été entièrement parcourue, 
    // la fonction copie les éléments restants de l'autre moitié dans tmp.
    if (i <= middle) {
        while (i <= middle) {
            tmp[k] = liste[i];
            i++;
            k++;
        }
    }
    else {
        while (j <= end) {
            tmp[k] = liste[j];
            j++;
            k++;
        }
    }

    // Copie les éléments triés de tmp dans liste
    for (k = 0; k < (end - start + 1); k++) {
        liste[start+k] = tmp[k];
    }

    free(tmp);
}

/**
 * \details : Tri optimisé (tri fusion) O(n*log(n))
 * \note : Tri Fusion qui utilise la technique de la "diviser pour régner" :
 * Cela divise une liste non triée en deux sous-listes de tailles presque égales, 
 * Puis tri chaque sous-liste de manière récursive en utilisant le même algorithme, 
 * Pour finir, cela fusionne les deux sous-listes triées pour obtenir la liste triée finale.
 * \param liste : Liste a trier
 * \param debut : Index de début de liste
 * \param fin : Index de fin de liste
 */
void merge_sort(uint32_t **liste, uint32_t debut, uint32_t fin) {
    if (debut < fin) {
        uint32_t milieu = (debut+fin)/2;
        merge_sort(liste, debut, milieu);
        merge_sort(liste, milieu+1, fin);
        merge(liste, debut, milieu, fin);
    }
}

/**
 * \details : Recherche élément commun
 * \param keys : Liste qui va contenir les clés trouvés
 * \param lm : Liste DES(m)
 * \param lc : Liste DES-1(c)
 * \param message_check : Registre de 24 bits d'un second message clair pour vérification des clés
 * \param cipher_check : Registre de 24 bits d'un second message chiffé pour vérification des clés
 * \return : Nombre de clés trouvées
 */
uint32_t common_elements(uint32_t keys[100][2], uint32_t **lm, uint32_t **lc, uint32_t message_check, uint32_t cipher_check) {

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
            // Le Pivot est utilisé pour pouvoir tester toutes les combinaisons possible dans le cas où il y a plusieurs valeurs égales,
            // il est la première valeur de la liste lc[j][0], et permettera de revenir à cette valeur pour chaque lm[i][0]
            if (lm[i][0] != pivot_value) {
                pivot = j;
                pivot_value = lc[j][0];
            }

            // On test la clé potentielle avec message_check et cipher_check
            double_encryption_res = double_encryption(message_check, lm[i][1], lc[j][1]);
            
            // Clé valide
            if (double_encryption_res == cipher_check) {

                keys[nb_keys][0] = lm[i][1];
                keys[nb_keys][1] = lc[j][1];

                nb_keys++;
            }

            // Gestion de l'incrémentation des index
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
    return nb_keys;
}

/**
 * \details : Attaque par le milieu sur PRESENT24
 * \note : Description de l'attaque
 *      Etape 1 => Génère listes Lm Lc de tailles 2^56
 *      Etape 2 => Pour chaque k de 0 jusqu'à 2^56 :
 *          - Lm = DES(m)
 *          - Lc = DES^-1(c) 
 *      Etape 3 => Tri listes Lm et Lc pour trouver les éléments communs plus rapidement
 *      Etape 4 => Recherche les éléments égaux dans les 2 tableaux
 *      Etape 5 => Test plusieurs couples clair/chiffré pour vérifier la validité des clés
 * \param clair : Registre de 24 bits d'un message clair
 * \param chiffré : Registre de 24 bits d'un message chiffré
 * \param clair2 : Registre de 24 bits d'un message clair
 * \param chiffré2 : Registre de 24 bits d'un message chiffré
 */
void attack(uint32_t clair, uint32_t chiffré, uint32_t clair2, uint32_t chiffré2) {

    // Chronomètre
    clock_t debut, fin;
    double tps_allocation, tps_fusion, tps_common;

    uint32_t size = 16777216; // 2^56

    // Résultat de l'attaque
    uint32_t keys[100][2];
    uint32_t number_keys = 0;

    uint32_t **lm = malloc(size * sizeof(int*));
    uint32_t **lc = malloc(size * sizeof(int*));
    
    uint32_t master_key;
    uint32_t k[11];
    uint32_t i;

    i = 0;


    // Allocation des listes Lm et Lc
    debut = clock();
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
    fin = clock();
    tps_allocation = (double)(fin - debut) / CLOCKS_PER_SEC;


    // Tri fusion des listes Lm et Lc
    debut = clock();
    merge_sort(lm, 0, size-1);
    merge_sort(lc, 0, size-1);

    fin = clock();
    tps_fusion = (double)(fin - debut) / CLOCKS_PER_SEC;


    // Recherche d'éléments communs
    debut = clock();
    number_keys = common_elements(keys, lm, lc, clair2, chiffré2);

    fin = clock();
    tps_common = (double)(fin - debut) / CLOCKS_PER_SEC;


    // Affiche le résultat de l'attaque
    printf("\nRésultat : %d clé(s) trouvé(es)\n", number_keys);
    for (i = 0; i < number_keys; i++) {
        printf("Clé %d : k1 = %#06x k2 = %#06x\n", i+1, keys[i][0], keys[i][1]);
    }
    printf("\nPerformance :\n - Création listes : %fs\n - Tri fusion : %fs\n - Recherche éléments communs : %fs\n", tps_allocation, tps_fusion, tps_common);

    // Désallocation des Listes Lm et Lc
    for (i = 0; i < size; i++) {
        free(lm[i]);
        free(lc[i]);
    }
    free(lm);
    free(lc);

    return;
};