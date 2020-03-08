#ifndef CONF_H
#define CONF_H

#include <stdint.h>
#include <stdio.h>

#include "ini.h"

#define INI_FILE_LOAD_FAILED 0
#define INI_FILE_LOAD_SUCCESS 1

#define INI_FLAGS_SECTION_NAME "flags"
#define INI_OTHER_SECTION_NAME "other"

#define CONFIGURATION_FILE_NAME "config.ini"

#define INI_ENCRYPT_FLAG "flag_value_encrypt"
#define INI_DECRYPT_FLAG "flag_value_decrypt"
#define INI_SET_KEY_FLAG "flag_value_key"
#define INI_SET_KEY_GENRATOR_ALPHABET_FLAG "flag_value_set_key_generator_alphabet"
#define INI_SHOW_KEY_GENERATOR_ALPHABET_FLAG "flag_value_show_key_generator_alphabet"
#define INI_SET_SUBSTITUTION_TABLE_FLAG "flag_value_set_substitution_table"
#define INI_SHOW_ASCII_CODES_FLAG "flag_value_show_ASCII_codes"
#define INI_SHOW_HELP_FLAG "flag_value_show_help"
#define INI_SUBSTITUTION_TABLE_FILE_NAME "substitution_table_file_name"
#define INI_SUBSTITUTION_TABLE_DEFAULT_NAME "substitution_table_default_name"
#define INI_KEY_GENERATOR_ALPHABET "key_generator_alphabet"

typedef struct
{
    uint8_t * flag_value_encrypt;
    uint8_t * flag_value_decrypt;
    uint8_t * flag_value_key;
    uint8_t * flag_value_set_key_generator_alphabet;
    uint8_t * flag_value_show_key_generator_alphabet;
    uint8_t * flag_value_set_substitution_table;
    uint8_t * flag_value_show_ASCII_codes;
    uint8_t * flag_value_show_help;
    uint8_t * substitution_table_file_name;
    uint8_t * key_generator_alphabet;
} configuration;

configuration config;

uint8_t load_config_file(uint8_t * config_file_name);

#endif

