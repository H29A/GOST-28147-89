#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#define BUFF_SIZE 8192
#define DEFAULT_KEY_GENERATOR_ALFABET "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

#define ARG_VALUE_KEY "-k"
#define ARG_VALUE_SET_KEY_GENERATOR_ALPHABET "-kga"
#define ARG_VALUE_SHOW_KEY_GENERATOR_ALPHABET "-skga"
#define ARG_VALUE_ENCRYPT "-e"
#define ARG_VALUE_DECRYPT "-d"
#define ARG_VALUE_HELP "-h"
#define ARG_VALUE_SHOW_ASCII "-sa"
#define ARG_VALUE_SET_SUBSTITUTION_TABLE "-t"
#define SUBSTITUTION_TABLE_CRYPTO_PRO_A "CP-A"
#define SUBSTITUTION_TABLE_CRYPTO_PRO_B "CP-B"
#define SUBSTITUTION_TABLE_CRYPTO_PRO_C "CP-C"
#define SUBSTITUTION_TABLE_CRYPTO_PRO_D "CP-D"

// Implementation of cyclical left shift
#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >> (-L & (N - 1)))) & (((uint64_t)1 << N) - 1))

static const struct substitutionTable {
    uint8_t CryptoPro_A[8][16];
    uint8_t CryptoPro_B[8][16];
    uint8_t CryptoPro_C[8][16];
    uint8_t CryptoPro_D[8][16];
} substitutionTable = {
    // Substitution table (identifier: id-Gost28147-89-CryptoPro-A-ParamSet)
    { 
        {0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5}, 
        {0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1},
        {0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9},
        {0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6},
        {0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6},
        {0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6},
        {0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE},
        {0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4},
    },

    // Substitution table (identifier: id-Gost28147-89-CryptoPro-B-ParamSet)
    { 
        {0x8, 0x4, 0xB, 0x1, 0x3, 0x5, 0x0, 0x9, 0x2, 0xE, 0xA, 0xC, 0xD, 0x6, 0x7, 0xF}, 
        {0x0, 0x1, 0x2, 0xA, 0x4, 0xD, 0x5, 0xC, 0x9, 0x7, 0x3, 0xF, 0xB, 0x8, 0x6, 0xE},
        {0xE, 0xC, 0x0, 0xA, 0x9, 0x2, 0xD, 0xB, 0x7, 0x5, 0x8, 0xF, 0x3, 0x6, 0x1, 0x4},
        {0x7, 0x5, 0x0, 0xD, 0xB, 0x6, 0x1, 0x2, 0x3, 0xA, 0xC, 0xF, 0x4, 0xE, 0x9, 0x8},
        {0x2, 0x7, 0xC, 0xF, 0x9, 0x5, 0xA, 0xB, 0x1, 0x4, 0x0, 0xD, 0x6, 0x8, 0xE, 0x3},
        {0x8, 0x3, 0x2, 0x6, 0x4, 0xD, 0x3, 0xB, 0xC, 0x1, 0x7, 0xF, 0xA, 0x0, 0x9, 0x5},
        {0x5, 0x2, 0xA, 0xB, 0x9, 0x1, 0xC, 0x3, 0x7, 0x4, 0xD, 0x0, 0x6, 0xF, 0x8, 0xE},
        {0x0, 0x4, 0xB, 0xE, 0x8, 0x3, 0x7, 0x1, 0xA, 0x2, 0x9, 0x6, 0xF, 0xD, 0x5, 0xC},
    },

    // Substitution table (identifier:id-Gost28147-89-CryptoPro-C-ParamSet)
    { 
        {0x1, 0xB, 0xC, 0x2, 0x9, 0xD, 0x0, 0xF, 0x4, 0x5, 0x8, 0xE, 0xA, 0x7, 0x6, 0x3}, 
        {0x0, 0x1, 0x7, 0xD, 0xB, 0x4, 0x5, 0x2, 0x8, 0xE, 0xF, 0xC, 0x9, 0xA, 0x6, 0x3},
        {0x8, 0x2, 0x5, 0x0, 0x4, 0x9, 0xF, 0xA, 0x3, 0x7, 0xC, 0xD, 0x6, 0xE, 0x1, 0xB},
        {0x3, 0x6, 0x0, 0x1, 0x5, 0xD, 0xA, 0x8, 0xB, 0x2, 0x9, 0x7, 0xE, 0xF, 0xC, 0x4},
        {0x8, 0xD, 0xB, 0x0, 0x4, 0x5, 0x1, 0x2, 0x9, 0x3, 0xC, 0xE, 0x6, 0xF, 0xA, 0x7},
        {0xC, 0x9, 0xB, 0x1, 0x8, 0xE, 0x2, 0x4, 0x7, 0x3, 0x6, 0x5, 0xA, 0x0, 0xF, 0xD},
        {0xA, 0x9, 0x6, 0x8, 0xD, 0xE, 0x2, 0x0, 0xF, 0x3, 0x5, 0xB, 0x4, 0x1, 0xC, 0x7},
        {0x7, 0x4, 0x0, 0x5, 0xA, 0x2, 0xF, 0xE, 0xC, 0x6, 0x1, 0xB, 0xD, 0x9, 0x3, 0x8},
    },

    // Substitution table (identifier: id-Gost28147-89-CryptoPro-D-ParamSet)
    { 
        {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3}, 
        {0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1},
        {0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2},
        {0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8},
        {0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1},
        {0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6},
        {0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7},
        {0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE},
    }
};

struct initial {
    bool encrypt;
    bool decrypt;
    bool showASCII;
    bool showKeyGeneratorAlphabet;
    bool needKeyGeneration;
    uint8_t key256bit[32];
    uint8_t * keyGeneratorAlphabet;
    uint8_t substitutionTable[8][16];
    uint8_t substitutionTableType[4];
} initial = { 
    false, 
    false, 
    false, 
    false,
    true,
    {0}, 
    DEFAULT_KEY_GENERATOR_ALFABET,
    {0},
    SUBSTITUTION_TABLE_CRYPTO_PRO_A
};

static inline void showUsage(uint8_t * argv);
static void * rand_string(uint8_t * str, uint8_t * alphabet, size_t size);
static inline void print_array(uint8_t * array, size_t length);
static inline void print_bits(uint64_t x, register uint64_t Nbit);

void split_256_bit_key_into_32_bit_parts(uint8_t * key256bit, uint32_t * keys32bit);
void split_64bits_to_32bits(uint64_t block64bit, uint32_t * block32bit_1, uint32_t * block32bit_2);
void split_64bits_to_8bits(uint64_t block64bit, uint8_t * blocks8bit);
void split_32bits_to_8bits(uint32_t block32bit, uint8_t * blocks8bit);

uint64_t join_32bits_to_64bits(uint32_t block32bit_1, uint32_t block32bit_2);
uint64_t join_8bits_to_64bits(uint8_t * blocks8bit);
uint32_t join_4bits_to_32bits(uint8_t * blocks4bit);

void substitution_table_by_4bits(uint8_t * blocks4bit, uint8_t sbox_row);
uint32_t substitution_table(uint32_t block32bit, uint8_t sbox_row);

void round_of_feistel_cipher(uint32_t * block32bit_1, uint32_t * block32bit_2, uint32_t * keys32bit, uint8_t round);
void feistel_cipher(uint8_t * mode, uint32_t * block32bit_1, uint32_t * block32bit_2, uint32_t * keys32bit);

size_t GOST_28147(uint8_t * to, uint8_t * mode, uint8_t * key256bit, uint8_t * from, size_t length);

void encrypt(uint8_t * key);
void decrypt(uint8_t * key);

int main(int argc, char *argv[]) {
    srand(time(NULL));

    memcpy(initial.substitutionTable, substitutionTable.CryptoPro_A, sizeof(initial.substitutionTable));
    strcpy(initial.substitutionTableType, SUBSTITUTION_TABLE_CRYPTO_PRO_A);

    for (uint8_t i = 0; i < argc; ++i) {
        if (strcmp(argv[i], ARG_VALUE_SET_KEY_GENERATOR_ALPHABET) == 0) {  
            if (i + 1 >= argc) {
                showUsage(argv[0]);
                _Exit(EXIT_FAILURE);
            }
            initial.showKeyGeneratorAlphabet = true;
            initial.keyGeneratorAlphabet = malloc(strlen(argv[i + 1]));
            strcpy(initial.keyGeneratorAlphabet, argv[i + 1]);
        }

        if (strcmp(argv[i], ARG_VALUE_SHOW_KEY_GENERATOR_ALPHABET) == 0) {
            initial.showKeyGeneratorAlphabet = true;
        }

        if (strcmp(argv[i], ARG_VALUE_SHOW_ASCII) == 0) {
            initial.showASCII = true;
        }

        if (strcmp(argv[i], ARG_VALUE_KEY) == 0) {
            if (i + 1 >= argc) {
                showUsage(argv[0]);
                _Exit(EXIT_FAILURE);
            }
            initial.needKeyGeneration = false;
            strcpy(initial.key256bit, argv[i+1]);
        }

        if (strcmp(argv[i], ARG_VALUE_DECRYPT) == 0) {
            initial.decrypt = true;
        }
        
        if (strcmp(argv[i], ARG_VALUE_ENCRYPT) == 0) {
            initial.encrypt = true;
        }

        if (strcmp(argv[i], ARG_VALUE_HELP) == 0 || argc <= 1) {
            showUsage(argv[0]);
        }

        if (strcmp(argv[i], ARG_VALUE_SET_SUBSTITUTION_TABLE) == 0) {
            if (i + 1 >= argc) {
                showUsage(argv[0]);
                _Exit(EXIT_FAILURE);
            }

            if (strcmp(argv[i + 1], SUBSTITUTION_TABLE_CRYPTO_PRO_A) == 0) {
                continue;
            } else if (strcmp(argv[i + 1], SUBSTITUTION_TABLE_CRYPTO_PRO_B) == 0) {
                strcpy(initial.substitutionTableType, SUBSTITUTION_TABLE_CRYPTO_PRO_B);
                memcpy(initial.substitutionTable, substitutionTable.CryptoPro_B, sizeof(initial.substitutionTable));
            } else if (strcmp(argv[i + 1], SUBSTITUTION_TABLE_CRYPTO_PRO_C) == 0) {
                strcpy(initial.substitutionTableType, SUBSTITUTION_TABLE_CRYPTO_PRO_C);
                memcpy(initial.substitutionTable, substitutionTable.CryptoPro_C, sizeof(initial.substitutionTable));
            } else if (strcmp(argv[i + 1], SUBSTITUTION_TABLE_CRYPTO_PRO_D) == 0) {
                strcpy(initial.substitutionTableType, SUBSTITUTION_TABLE_CRYPTO_PRO_D);
                memcpy(initial.substitutionTable, substitutionTable.CryptoPro_D, sizeof(initial.substitutionTable));
            } else {
                showUsage(argv[0]);
                _Exit(EXIT_FAILURE);
            }
        }
    }

    if (initial.needKeyGeneration == true) {
        strcpy(initial.key256bit, rand_string(initial.key256bit, initial.keyGeneratorAlphabet, sizeof(uint8_t) * 32));
    }

    if (initial.encrypt == true) {
        encrypt(initial.key256bit);
    }

    if (initial.decrypt == true) {
        decrypt(initial.key256bit);
    }

    return EXIT_SUCCESS;
}

void encrypt(uint8_t * key) {
    uint8_t data[BUFF_SIZE] = {0};
    uint8_t buffer[BUFF_SIZE] = {0};

    uint8_t character;
    size_t position = 0;

    printf("\nWrite the message you need to encrypt: ");
    while ((character = getchar()) != '\n' && position < BUFF_SIZE - 1) {
        buffer[position++] = character;
    }
    buffer[position] = '\0';

    position = GOST_28147(data, ARG_VALUE_ENCRYPT, key, buffer, position);

    printf("Substitution table type: %s\n", initial.substitutionTableType);
    printf("Key: [%s]\n", key);

    if (initial.showKeyGeneratorAlphabet == true) {
        printf("Key generator alphabet: [%s]\n", initial.keyGeneratorAlphabet);
    }

    printf("Encrypted message: [%s]\n", data);

    if (initial.showASCII == true) {
        printf("ASCII encrypted message: ");
        print_array(data, position);
    }
}

void decrypt(uint8_t * key) {
    uint8_t data[BUFF_SIZE] = {0};
    uint8_t buffer[BUFF_SIZE] = {0};

    uint8_t character;
    size_t position = 0;

    printf("\nWrite the message you need to decrypt: ");
    while ((character = getchar()) != '\n' && position < BUFF_SIZE - 1) {
        buffer[position++] = character;
    }
    buffer[position] = '\0';

    position = GOST_28147(data, ARG_VALUE_DECRYPT, key, buffer, position);

    printf("Substitution table type: %s\n", initial.substitutionTableType);
    printf("Key: [%s]\n", key);

    if (initial.showKeyGeneratorAlphabet == true) {
        printf("Key generator alphabet: [%s]\n", initial.keyGeneratorAlphabet);
    }

    printf("Decrypted message: [%s]\n", data);

    if (initial.showASCII == true) {
        printf("ASCII decrypted message: ");
        print_array(data, position);
    }
}

// Generation of subkeys from the main 256-bit key by splitting into eight 32-bit keys (K0...K7)
void split_256_bit_key_into_32_bit_parts(uint8_t * key256bit, uint32_t * keys32bit) {
    int8_t * pKey256bit = key256bit;
    for (uint32_t *pKeys32bit = keys32bit; pKeys32bit < keys32bit + 8; ++pKeys32bit) {
        for (uint8_t i = 0; i < 4; ++i) {
            *pKeys32bit = (*pKeys32bit << 8) | *(pKey256bit + i);
        }
        pKey256bit += 4;
    }
}

// Join 64-bit block from 8-bit (needed to create a 64-bit block of 8-bit characters)
uint64_t join_8bits_to_64bits(uint8_t * blocks8bit) {
    uint64_t block64bit;
    for (uint8_t *pBlocks8bit = blocks8bit; pBlocks8bit < blocks8bit + 8; ++pBlocks8bit) {
        block64bit = (block64bit << 8) | *pBlocks8bit;
    }
    return block64bit;
}

// Splitting 64-bit block into two 32-bit parts (N1 and N2)
void split_64bits_to_32bits(uint64_t block64bit, uint32_t * block32bit_1, uint32_t * block32bit_2) {
    *block32bit_2 = (uint32_t)(block64bit);
    *block32bit_1 = (uint32_t)(block64bit >> 32);
}

void split_64bits_to_8bits(uint64_t block64bit, uint8_t * blocks8bit) {
    for (size_t i = 0; i < 8; ++i) {
        blocks8bit[i] = (uint8_t)(block64bit >> ((7 - i) * 8));
    }
}

// Splitting 32-bit block into four 8-bit parts (values to be replaced by numbers from the replacement table)
void split_32bits_to_8bits(uint32_t block32bit, uint8_t * blocks8bit) {
    for (uint8_t i = 0; i < 4; ++i) {
        blocks8bit[i] = (uint8_t)(block32bit >> (24 - (i * 8)));
    }
}

// Perform a replacement 4-bit blocks using substution table
void substitution_table_by_4bits(uint8_t * blocks4bit, uint8_t sbox_row) {
    uint8_t block4bit_1, block4bit_2;
    for (uint8_t i = 0; i < 4; ++i) {
        // Get right half of 8-bit block and do replacement
        block4bit_1 = initial.substitutionTable[sbox_row][blocks4bit[i] & 0x0F]; 

        // Get left half of 8-bit block and do replacement
        block4bit_2 = initial.substitutionTable[sbox_row][blocks4bit[i] >> 4];

        // Concat in 8-bit
        blocks4bit[i] = (block4bit_2 << 4) | block4bit_1; 
    }
}

// Join a 32-bit block of 8-bit (4-bit) blocks after replacement using substitution table
uint32_t join_4bits_to_32bits(uint8_t * blocks4bit) {
    uint32_t block32bit;
    for (uint8_t i = 0; i < 4; ++i) {
        block32bit = (block32bit << 8) | blocks4bit[i];
    }
    return block32bit;
}

// Creating 32-bit block using substitution table
uint32_t substitution_table(uint32_t block32bit, uint8_t sbox_row) {
    uint8_t blocks4bits[4];
    split_32bits_to_8bits(block32bit, blocks4bits);
    substitution_table_by_4bits(blocks4bits, sbox_row);
    return join_4bits_to_32bits(blocks4bits);
}

void round_of_feistel_cipher(uint32_t * block32bit_1, uint32_t * block32bit_2, uint32_t * keys32bit, uint8_t round) {
    uint32_t result_of_iter, temp;

    // RES = (N1 + Ki) mod 2^32
    result_of_iter = (*block32bit_1 + keys32bit[round % 8]) % UINT32_MAX;
    
    // RES = RES -> Sbox
    result_of_iter = substitution_table(result_of_iter, round % 8);
    
    // RES = RES <<< 11
    result_of_iter = (uint32_t)LSHIFT_nBIT(result_of_iter, 11, 32);

    // N1, N2 = (RES xor N2), N1
    temp = *block32bit_1;
    *block32bit_1 = result_of_iter ^ *block32bit_2;
    *block32bit_2 = temp;
}

void feistel_cipher(uint8_t * mode, uint32_t * block32bit_1, uint32_t * block32bit_2, uint32_t * keys32bit) {

    if (strcmp(mode, ARG_VALUE_DECRYPT) == 0) {
        // K0, K1, K2, K3, K4, K5, K6, K7
            for (uint8_t round = 0; round < 8; ++round)
                round_of_feistel_cipher(block32bit_1, block32bit_2, keys32bit, round);

            // K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0
            for (uint8_t round = 31; round >= 8; --round)
                round_of_feistel_cipher(block32bit_1, block32bit_2, keys32bit, round);
    }

    if (strcmp(mode, ARG_VALUE_ENCRYPT) == 0) {
        // K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7
            for (uint8_t round = 0; round < 24; ++round)
                round_of_feistel_cipher(block32bit_1, block32bit_2, keys32bit, round);

            // K7, K6, K5, K4, K3, K2, K1, K0
            for (uint8_t round = 31; round >= 24; --round)
                round_of_feistel_cipher(block32bit_1, block32bit_2, keys32bit, round);
    }
}

uint64_t join_32bits_to_64bits(uint32_t block32bit_1, uint32_t block32bit_2) {
    uint64_t block64b;
    block64b = block32bit_2;
    block64b = (block64b << 32) | block32bit_1;
    return block64b;
}

size_t GOST_28147(uint8_t * to, uint8_t * mode, uint8_t * key256bit, uint8_t * from, size_t length) {
    length = length % 8 == 0 ? length : length + (8 - (length % 8));
    uint32_t N1, N2, keys32bit[8];
    split_256_bit_key_into_32_bit_parts(key256bit, keys32bit);

    for (size_t i = 0; i < length; i += 8) {
        split_64bits_to_32bits(
            join_8bits_to_64bits(from + i), 
            &N1, &N2
        );
        feistel_cipher(mode, &N1, &N2, keys32bit);
        split_64bits_to_8bits(
            join_32bits_to_64bits(N1, N2),
            (to + i)
        );
    }

    return length;
}

static inline void showUsage(uint8_t * argv) {
    printf("\nUsage: %s [%s <table_type>] [%s <string_key>] [%s <string_alphabet>] [%s] [%s] [%s] [%s] [%s]\n", argv,  ARG_VALUE_SET_SUBSTITUTION_TABLE, ARG_VALUE_KEY, ARG_VALUE_SET_KEY_GENERATOR_ALPHABET, ARG_VALUE_SHOW_KEY_GENERATOR_ALPHABET, ARG_VALUE_ENCRYPT, ARG_VALUE_DECRYPT, ARG_VALUE_SHOW_ASCII, ARG_VALUE_HELP);
    printf("Options: \n");
    printf("  %-6s   <table_type>     \tSet type of substitution table.  (default: %s).\n", ARG_VALUE_SET_SUBSTITUTION_TABLE, SUBSTITUTION_TABLE_CRYPTO_PRO_A, SUBSTITUTION_TABLE_CRYPTO_PRO_B, SUBSTITUTION_TABLE_CRYPTO_PRO_C, SUBSTITUTION_TABLE_CRYPTO_PRO_D, SUBSTITUTION_TABLE_CRYPTO_PRO_A); 
    printf("                          \tReplacement units are defined in RFC 4357 (https://tools.ietf.org/html/rfc4357).\n");
    printf("                          \tThere are four types available: [%s], [%s], [%s] and [%s].\n", SUBSTITUTION_TABLE_CRYPTO_PRO_A, SUBSTITUTION_TABLE_CRYPTO_PRO_B, SUBSTITUTION_TABLE_CRYPTO_PRO_C, SUBSTITUTION_TABLE_CRYPTO_PRO_D); 
    printf("                          \tWhere CP means CryptoPro, hyphen letter means table modification. \n");
    printf("  %-6s   <string_key>     \tSet 256-bit key for encrypting/decrypting (default: randomly generated).\n", ARG_VALUE_KEY);
    printf("  %-6s   <string_alphabet>\tSet the key generation alphabet (default: 0-9a-zA-Z).\n", ARG_VALUE_SET_KEY_GENERATOR_ALPHABET);
    printf("  %-6s                   \tDisplay the key generation alphabet (default: off).\n", ARG_VALUE_SHOW_KEY_GENERATOR_ALPHABET);
    printf("  %-6s                   \tEncrypting operation.\n", ARG_VALUE_ENCRYPT);
    printf("  %-6s                   \tDecrypting operation.\n", ARG_VALUE_DECRYPT);
    printf("  %-6s                   \tDisplay the result also through ASCII table codes (default: off).\n", ARG_VALUE_SHOW_ASCII);
    printf("  %-6s                   \tShow tooltips.\n", ARG_VALUE_HELP);
}

static void * rand_string(uint8_t * str, uint8_t * alphabet, size_t size)
{
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (strlen(alphabet));
            str[n] = alphabet[key];
        }
        str[size] = '\0';
    }
    return str;
}


static void print_array(uint8_t * array, size_t length) {
    printf("[ ");
    for (size_t i = 0; i < length; ++i) {
        printf("%d ", array[i]);
    }
    printf("]\n");
}

static void print_bits(uint64_t x, register uint64_t Nbit) {
    for (Nbit = (uint64_t)1 << (Nbit - 1); Nbit > 0x00; Nbit >>= 1) {
        printf("%d", (x & Nbit) ? 1 : 0);
    }
    putchar('\n');
}