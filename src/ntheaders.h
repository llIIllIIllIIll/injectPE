#pragma once

#include <stdint.h>

// Magic Numbers
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_OS2_SIGNATURE 0x454E
#define IMAGE_OS2_SIGNATURE_LE 0x454C
#define IMAGE_NT_SIGNATURE 0x4550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_SIZEOF_SHORT_NAME 0x8
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 0x10

// Directory Entries
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

// Machine Types
#define IMAGE_FILE_MACHINE_UNKNOWN 0x0
#define IMAGE_FILE_MACHINE_AM33 0x1d3
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARM  0x1c0
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_ARMNT 0x1c4
#define IMAGE_FILE_MACHINE_EBC 0xebc
#define IMAGE_FILE_MACHINE_I386 0x14c
#define IMAGE_FILE_MACHINE_IA64 0x200
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define IMAGE_FILE_MACHINE_MIPS16 0x266
#define IMAGE_FILE_MACHINE_MIPSFPU 0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x466
#define IMAGE_FILE_MACHINE_POWERPC 0x1f0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x1f1
#define IMAGE_FILE_MACHINE_R4000 0x166   
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064
#define IMAGE_FILE_MACHINE_RISCV128 0x5128
#define IMAGE_FILE_MACHINE_SH3 0x1a2
#define IMAGE_FILE_MACHINE_SH3DSP 0x1a3     
#define IMAGE_FILE_MACHINE_SH4 0x1a6
#define IMAGE_FILE_MACHINE_SH5 0x1a8
#define IMAGE_FILE_MACHINE_THUMB 0x1c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x169

// Image Characteristics
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000

// Dll Characteristics
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x20
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x40
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x80
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

// Section Flags
#define IMAGE_SCN_TYPE_NO_PAD 0x8
#define IMAGE_SCN_CNT_CODE 0x20
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x40
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x80
#define IMAGE_SCN_LNK_OTHER 0x100
#define IMAGE_SCN_LNK_INFO 0x200
#define IMAGE_SCN_LNK_REMOVE 0x800
#define IMAGE_SCN_LNK_COMDAT 0x1000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x4000
#define IMAGE_SCN_GPREL 0x8000
#define IMAGE_SCN_MEM_PURGEABLE 0x20000
//#define IMAGE_SCN_MEM_16BIT
#define IMAGE_SCN_MEM_LOCKED 0x40000
#define IMAGE_SCN_MEM_PRELOAD 0x80000
#define IMAGE_SCN_ALIGN_1BYTES 0x100000
#define IMAGE_SCN_ALIGN_2BYTES 0x200000
#define IMAGE_SCN_ALIGN_4BYTES 0x300000
#define IMAGE_SCN_ALIGN_8BYTES 0x400000
#define IMAGE_SCN_ALIGN_16BYTES 0x500000
#define IMAGE_SCN_ALIGN_32BYTES 0x600000
#define IMAGE_SCN_ALIGN_64BYTES 0x700000
#define IMAGE_SCN_ALIGN_128BYTES 0x800000
#define IMAGE_SCN_ALIGN_256BYTES 0x900000
#define IMAGE_SCN_ALIGN_512BYTES 0xA00000
#define IMAGE_SCN_ALIGN_1024BYTES 0xB00000
#define IMAGE_SCN_ALIGN_2048BYTES 0xC00000
#define IMAGE_SCN_ALIGN_4096BYTES 0xD00000
#define IMAGE_SCN_ALIGN_8192BYTES 0xE00000
#define IMAGE_SCN_LNK_NRELOC_OVFL 0x1000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x2000000
#define IMAGE_SCN_MEM_NOT_CACHED 0x4000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x8000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

/* Windows PE structures */

typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    uint32_t Name;
    uint32_t OffsetToData;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;
    uint8_t Name[];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t *AddressOfFunctions;
    uint32_t *AddressOfNames;
    uint32_t *AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
