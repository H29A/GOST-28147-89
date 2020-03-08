#include "conf.h"

uint8_t load_config_file(uint8_t * config_file_name) {   
    
    ini_t * config_file = ini_load(config_file_name);

    if (!config_file) {
        printf("Can't load \"%s\"\n", config_file_name);
        return INI_FILE_LOAD_FAILED;
    }

    config.flag_value_encrypt = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_ENCRYPT_FLAG);
    config.flag_value_decrypt = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_DECRYPT_FLAG);
    config.flag_value_key = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_SET_KEY_FLAG);
    config.flag_value_set_key_generator_alphabet = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_SET_KEY_GENRATOR_ALPHABET_FLAG);
    config.flag_value_show_key_generator_alphabet = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_SHOW_KEY_GENERATOR_ALPHABET_FLAG);
    config.flag_value_set_substitution_table = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_SET_SUBSTITUTION_TABLE_FLAG);
    config.flag_value_show_ASCII_codes = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_SHOW_ASCII_CODES_FLAG);
    config.flag_value_show_help = ini_get(config_file, INI_FLAGS_SECTION_NAME, INI_SHOW_HELP_FLAG);
    config.substitution_table_file_name = ini_get(config_file, INI_OTHER_SECTION_NAME, INI_SUBSTITUTION_TABLE_FILE_NAME);
    config.key_generator_alphabet = ini_get(config_file, INI_OTHER_SECTION_NAME, INI_KEY_GENERATOR_ALPHABET);



    if (!(config.flag_value_encrypt && config.flag_value_decrypt && config.flag_value_key &&
        config.flag_value_set_key_generator_alphabet && config.flag_value_show_key_generator_alphabet &&
        config.flag_value_set_substitution_table && config.flag_value_show_ASCII_codes &&
        config.flag_value_show_help && config.substitution_table_file_name && config.key_generator_alphabet)) {
            printf("Failed while parsing \"%s\" file. Check for all fields.\n", config_file_name);
            return INI_FILE_LOAD_FAILED;
    }

    return INI_FILE_LOAD_SUCCESS;
}