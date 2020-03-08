#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <jansson.h>
#include "conf.h"

#define BUFF_SIZE 8192

#define STRSWITCH(STR)      uint8_t _x[16]; strcpy(_x, STR); if (false)
#define STRCASE(STR)        } else if (strcmp(_x, STR)==0){
#define STRDEFAULT          } else {

// Implementation of cyclical left shift
#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >> (-L & (N - 1)))) & (((uint64_t)1 << N) - 1))

struct initial {
    bool encrypt;
    bool decrypt;
    bool show_ASCII;
    bool show_key_generator_alphabet;
    bool need_key_generation;
    uint8_t key_256_bit[32];
    uint8_t substitution_table[8][16];
    const uint8_t * substitution_table_name;
} initial = { 
    false, 
    false, 
    false, 
    false,
    true,
    {0},
    {0}
};

static inline void showUsage();
static void * rand_string(uint8_t * str, uint8_t * alphabet, size_t size);
static inline void print_array(uint8_t * array, size_t length);
static inline void print_bits(uint64_t x, register uint64_t Nbit);

void split_256_bit_key_into_32_bit_parts(uint8_t * key_256_bit, uint32_t * keys32bit);
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

size_t GOST_28147(uint8_t * to, uint8_t * mode, uint8_t * key_256_bit, uint8_t * from, size_t length);

void encrypt(uint8_t * key);
void decrypt(uint8_t * key);

void exit_failure() {
    showUsage();
    _Exit(EXIT_FAILURE);
}

void check_next_argv(uint8_t argc, uint8_t * argv, uint8_t i) {
    if (i + 1 >= argc) {
        printf("Failed then read flag [%s], please check halp info\n", argv);
        exit_failure();
    }
}

void load_replacement_table(uint8_t * tables_file, uint8_t * table_name) {
    json_error_t error;
    json_t * tables = json_load_file(tables_file, 0, &error);

    if (!tables) {
        printf("Failed while loading %s\n", tables_file);
        printf("json error: %s:%d:%d: %s\n", error.source, error.line, error.column, error.text);
        exit_failure();
    }

    json_t * loaded_table = json_object_get(tables, table_name);

    if (!loaded_table) {
        printf("Failed when trying get %s in %s file\n", table_name, tables_file);
        exit_failure();
    } else if (!json_is_array(loaded_table)) {
        printf("%s in %s is not an array\n", table_name, tables_file);
        exit_failure();
    }

    printf("Table \"%s\" loaded successfully\n", table_name);

    size_t first_dimension_index;
    json_t * first_dimension_array_value;
    json_array_foreach(loaded_table, first_dimension_index, first_dimension_array_value) {
        size_t second_dimension_index;
        json_t * second_dimension_array_value;
        json_array_foreach(json_array_get(loaded_table, first_dimension_index), second_dimension_index, second_dimension_array_value) {
            initial.substitution_table[first_dimension_index][second_dimension_index] = strtol(json_string_value(second_dimension_array_value), NULL, 0x10);
        }
    }
}

int main(int32_t argc, uint8_t *argv[]) {
    srand(time(NULL));

    if(!load_config_file(CONFIGURATION_FILE_NAME)) {
        return EXIT_FAILURE;
    }

    if (argc <= 1) {
        exit_failure();
    }

    for (uint8_t i = 0; i < argc; ++i) {
        STRSWITCH(argv[i])
        {
            STRCASE (config.flag_value_encrypt)    
                initial.encrypt = true;    

            STRCASE (config.flag_value_decrypt)    
                initial.decrypt = true;

            STRCASE (config.flag_value_set_key_generator_alphabet)
                check_next_argv(argc, argv[i], i);
                initial.show_key_generator_alphabet = true;
                config.key_generator_alphabet = malloc(strlen(argv[i + 1]));
                strcpy(config.key_generator_alphabet, argv[i + 1]);

            STRCASE (config.flag_value_show_key_generator_alphabet)
                initial.show_key_generator_alphabet = true;

            STRCASE (config.flag_value_show_ASCII_codes)
                initial.show_ASCII = true;

            STRCASE (config.flag_value_key)
                check_next_argv(argc, argv[i], i);
                initial.need_key_generation = false;
                strcpy(initial.key_256_bit, argv[i+1]);

            STRCASE (config.flag_value_show_help)    
                showUsage();

            STRCASE (config.flag_value_set_substitution_table) 
                check_next_argv(argc, argv[i], i);   
                load_replacement_table(config.substitution_table_file_name, argv[i + 1]);
                initial.substitution_table_name = argv[i + 1];
        }
    }


    if (!initial.substitution_table_name) {
        printf("You must select a replacement table\n");
        exit_failure();
    }
    
    if (initial.need_key_generation) 
    {
        strcpy(initial.key_256_bit, rand_string(initial.key_256_bit, config.key_generator_alphabet, sizeof(uint8_t) * 32));
    }

    if (initial.encrypt) {
        encrypt(initial.key_256_bit);
    } else if (initial.decrypt) {
        decrypt(initial.key_256_bit);
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

    position = GOST_28147(data, config.flag_value_encrypt, key, buffer, position);

    printf("Substitution table type: %s\n", initial.substitution_table_name);
    printf("Key: [%s]\n", key);

    if (initial.show_key_generator_alphabet == true) {
        printf("Key generator alphabet: [%s]\n", config.key_generator_alphabet);
    }

    printf("Encrypted message: [%s]\n", data);

    if (initial.show_ASCII == true) {
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

    position = GOST_28147(data, config.flag_value_decrypt, key, buffer, position);

    printf("Substitution table type: %s\n", initial.substitution_table_name);
    printf("Key: [%s]\n", key);

    if (initial.show_key_generator_alphabet == true) {
        printf("Key generator alphabet: [%s]\n", config.key_generator_alphabet);
    }

    printf("Decrypted message: [%s]\n", data);

    if (initial.show_ASCII == true) {
        printf("ASCII decrypted message: ");
        print_array(data, position);
    }
}

// Generation of subkeys from the main 256-bit key by splitting into eight 32-bit keys (K0...K7)
void split_256_bit_key_into_32_bit_parts(uint8_t * key_256_bit, uint32_t * keys32bit) {
    int8_t * pkey_256_bit = key_256_bit;
    for (uint32_t *pKeys32bit = keys32bit; pKeys32bit < keys32bit + 8; ++pKeys32bit) {
        for (uint8_t i = 0; i < 4; ++i) {
            *pKeys32bit = (*pKeys32bit << 8) | *(pkey_256_bit + i);
        }
        pkey_256_bit += 4;
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
        block4bit_1 = initial.substitution_table[sbox_row][blocks4bit[i] & 0x0F]; 

        // Get left half of 8-bit block and do replacement
        block4bit_2 = initial.substitution_table[sbox_row][blocks4bit[i] >> 4];

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

    if (strcmp(mode, config.flag_value_decrypt) == 0) {
        // K0, K1, K2, K3, K4, K5, K6, K7
            for (uint8_t round = 0; round < 8; ++round)
                round_of_feistel_cipher(block32bit_1, block32bit_2, keys32bit, round);

            // K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0
            for (uint8_t round = 31; round >= 8; --round)
                round_of_feistel_cipher(block32bit_1, block32bit_2, keys32bit, round);
    }

    if (strcmp(mode, config.flag_value_encrypt) == 0) {
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

size_t GOST_28147(uint8_t * to, uint8_t * mode, uint8_t * key_256_bit, uint8_t * from, size_t length) {
    length = length % 8 == 0 ? length : length + (8 - (length % 8));
    uint32_t N1, N2, keys32bit[8];
    split_256_bit_key_into_32_bit_parts(key_256_bit, keys32bit);

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

static inline void showUsage() {
    printf("\nUsage: GOST_28147-89.exe [%s <table_name>] [%s <string_key>] [%s <string_alphabet>] [%s] [%s] [%s] [%s] [%s]\n\n",  config.flag_value_set_substitution_table, config.flag_value_key, config.flag_value_set_key_generator_alphabet, config.flag_value_show_key_generator_alphabet, config.flag_value_encrypt, config.flag_value_decrypt, config.flag_value_show_ASCII_codes, config.flag_value_show_help);
    printf("Options: \n");
    printf("  %-12s   <table_name>     \tSet substitution table from %s file.\n", config.flag_value_set_substitution_table, config.substitution_table_file_name);                     
    printf("  %-12s   <string_key>     \tSet 256-bit key for encrypting/decrypting (default: randomly generated).\n", config.flag_value_key);
    printf("  %-12s   <string_alphabet>\tSet the key generation alphabet (default: 0-9a-zA-Z).\n", config.flag_value_set_key_generator_alphabet);
    printf("  %-12s                   \tDisplay the key generation alphabet (default: off).\n", config.flag_value_show_key_generator_alphabet);
    printf("  %-12s                   \tEncrypting operation.\n", config.flag_value_encrypt);
    printf("  %-12s                   \tDecrypting operation.\n", config.flag_value_decrypt);
    printf("  %-12s                   \tDisplay the result also through ASCII table codes (default: off).\n", config.flag_value_show_ASCII_codes);
    printf("  %-12s                   \tShow tooltips.\n", config.flag_value_show_help);
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