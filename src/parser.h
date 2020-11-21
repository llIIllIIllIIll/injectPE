#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "ntheaders.h"

#define EXTEND_CODE 0
#define NEW_SECTION 1
#define CODE_CAVE 2

class IMAGE {
public:
    IMAGE(const char *path);

    uint8_t read_byte(uint32_t offset);
    uint16_t read_word(uint32_t offset);
    uint32_t read_dword(uint32_t offset);
    uint64_t read_qword(uint32_t offset);
    uint32_t addr_to_offset(uint64_t address);
    uint64_t offset_to_addr(uint32_t offset);

    bool copy(void *dst, uint32_t offset, uint32_t bytes);
    bool write(void *src, uint32_t offset, uint32_t bytes);
    bool inject(char *path, uint8_t *shellcode, uint32_t size, uint32_t type);

    bool is32(void);
    bool is64(void);

    ~IMAGE(void);

private:
    typedef struct _IMAGE_INJECT_INFO {
        bool is_extended;
        uint32_t section_index;
        uint32_t extention_size;
        uint32_t original_size;
        uint32_t original_ep;
        uint32_t ptr_to_data;
        uint32_t shellcode_size;
        IMAGE_SECTION_HEADER *section;
    } IMAGE_INJECT_INFO;

    void destroy(void);
    bool get_headers(void);
    bool get_opt_headers(void);
    bool get_sections(void);
    void set(uint32_t offset);

private:
    FILE *pe_file;
    uint32_t current_offset;
    uint32_t file_size;
    uint32_t magic;

    IMAGE_DOS_HEADER *dos_header;
    IMAGE_FILE_HEADER *file_header;
    IMAGE_SECTION_HEADER **sections;

    union {
        IMAGE_OPTIONAL_HEADER32 *optional_header32;
        IMAGE_OPTIONAL_HEADER64 *optional_header64;
    };

private:
    IMAGE_SECTION_HEADER * get_section_by_name(char *section);
    IMAGE_SECTION_HEADER * get_section_by_offset(uint32_t offset);

    uint32_t align(uint32_t value, uint32_t alignment);
    uint32_t update_entry_point(IMAGE_INJECT_INFO *info, uint32_t type);
    uint8_t * create_new_file(IMAGE_INJECT_INFO *info);

    bool find_code_cave(IMAGE_INJECT_INFO *info, uint32_t size);
    bool append_new_section(IMAGE_INJECT_INFO *info, uint32_t size);
    bool extend_text_section(IMAGE_INJECT_INFO *info, uint32_t size);
    bool write_file(uint8_t *file, char *path, IMAGE_INJECT_INFO *info);
};
