uint32_t substitution(uint32_t etat, int* S);
uint32_t permutation(uint32_t etat, int* P);

void key_schedule(uint32_t master_key, uint32_t* k, int* S);

uint32_t encryption(uint32_t message, uint32_t* k);