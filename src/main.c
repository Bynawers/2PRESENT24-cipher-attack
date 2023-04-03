#include <stdio.h>
#include <time.h>
#include "stdint.h"

#include "attack.h"

int main() {

    // Chronomètre
    clock_t debut, fin;
    double temps_ecoule;
    debut = clock();

    /**  PRESENT24   **/

    uint32_t m1, m2;
    uint32_t c1, c2;

    m1 = 0x3af44f;
    c1 = 0x1b231a;
    m2 = 0xe568ff;
    c2 = 0x4afd12;

    attack(m1, c1, m2, c2);
    
    /**   FIN   **/

    // Calcul et affiche le temps écoulé en secondes
    fin = clock();
    temps_ecoule = (double)(fin - debut) / CLOCKS_PER_SEC;
    printf("Le temps d'execution est de %f secondes.\n", temps_ecoule);

    return 0;
}