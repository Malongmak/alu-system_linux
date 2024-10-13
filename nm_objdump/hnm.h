#ifndef _HNM_
#define _HNM_

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>

/**
* struct header32 - Represents a 32-bit ELF header.
* Structure represents a 32-bit ELF (Executable and Linkable Format) header.
* It includes a member named 'ehdr' of type 'Elf32_Ehdr', which holds the main
* ELF header information.
* ELF header provides essential information about the ELF file format, such
* as its class (32-bit), data encoding, file type, machine architecture, entry
* point, program header and section header information, and more.
* @ehdr: structure is typically used for parsing and working with 32-bit ELF
*/
typedef struct header32
{
	Elf32_Ehdr ehdr;
} Elf32_Header;

/**
* struct Shdr32 - Represents a 32-bit ELF section header.
*
* This structure represents a 32-bit ELF section header. It includes a member
* named 'shdr' of type 'Elf32_Shdr' for storing information about individual
* sections within the ELF file. Section headers provide details about the
* layout and characteristics of various sections in the ELF file.
*
* @shdr: A structure of type 'Elf32_Shdr' used for parsing and working with
* 32-bit ELF section headers.
*/
typedef struct Shdr32
{
	Elf32_Shdr shdr;
} MyElf32_Shdr;

/**
* Elf32_Sym - Represents a 32-bit ELF symbol entry.
*
* This structure is used to represent an entry for a symbol in a 32-bit ELF
* (Executable and Linkable Format) file. Each field within the structure holds
* specific information about the symbol, such as its name (an offset in the
* string table), value or address, size, type, binding, visibility, and the
* index of the section to which the symbol belongs.
*
* @st_name: Offset to the symbol name in the string table.
* @st_value: Value or address associated with the symbol.
* @st_size: Size of the symbol in bytes.
* @st_info: Symbol type and binding information.
* @st_other: Symbol visibility.
* @st_shndx: Index of the section to which the symbol belongs.
*/
typedef struct
{
	Elf32_Word st_name;
	Elf32_Addr st_value;
	Elf32_Word st_size;
	unsigned char st_info;
	unsigned char st_other;
	Elf32_Half st_shndx;
} MyElf32_Sym;

/* struct for 64 bits */
/**
* struct header64 - Represents a 64-bit ELF header.
* Structure represents a 64-bit ELF (Executable and Linkable Format) header.
* It includes a member named 'ehdr' of type 'Elf64_Ehdr', which holds the main
* ELF header information.
* ELF header provides essential information about the ELF file format, such
* as its class (64-bit), data encoding, file type, machine architecture, entry
* point, program header and section header information, and more.
* @ehdr: structure is typically used for parsing and working with 64-bit ELF
*/
typedef struct header64
{
	Elf64_Ehdr ehdr;
} Elf64_Header;

/**
* struct Shdr64 - Represents a 64-bit ELF section header.
*
* This structure represents a 64-bit ELF section header. It includes a member
* named 'shdr' of type 'Elf64_Shdr' for storing information about individual
* sections within the ELF file. Section headers provide details about the
* layout and characteristics of various sections in the ELF file.
*
* @shdr: A structure of type 'Elf64_Shdr' used for parsing and working with
* 64-bit ELF section headers.
*/
typedef struct Shdr64
{
	Elf64_Shdr shdr;
} MyElf64_Shdr;

/**
* MyElf64_Sym - Represents a 64-bit ELF symbol entry.
*
* This structure is used to represent an entry for a symbol in a 64-bit ELF
* (Executable and Linkable Format) file. Each field within the structure holds
* specific information about the symbol, such as its name (an offset in the
* string table), value or address, size, type, binding, visibility, and the
* index of the section to which the symbol belongs.
*
* @st_name: Offset to the symbol name in the string table.
* @st_value: Value or address associated with the symbol.
* @st_size: Size of the symbol in bytes.
* @st_info: Symbol type and binding information.
* @st_other: Symbol visibility.
* @st_shndx: Index of the section to which the symbol belongs.
*/
typedef struct
{
	Elf64_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Elf64_Half st_shndx;
	Elf64_Addr st_value;
	Elf64_Xword st_size;
} MyElf64_Sym;

/* Funtions Task 0*/
int analyze_file(const char *filename);
int analyze_64bit_elf(Elf64_Ehdr *ehdr, void *map, const char *filename);
void process_symbols_64bit(Elf64_Ehdr *ehdr, void *map, const char *filename);
const char *get_symbol_type_64(uint8_t info, Elf64_Sym sym, Elf64_Shdr *shdr);

int analyze_32bit_elf(Elf32_Ehdr *ehdr, void *map, const char *filename);
void process_symbols_32bit(Elf32_Ehdr *ehdr, void *map, const char *filename);
const char *get_symbol_type_32(uint8_t info, Elf32_Sym sym, Elf32_Shdr *shdr);

void process_symbols_32bit_big_endian(Elf32_Ehdr *ehdr, void *map,
										const char *filename);
uint32_t byteswap32(uint32_t value);
uint16_t byteswap16(uint16_t value);

void process_symbols_32bit_solaris(Elf32_Ehdr *ehdr, void *map,
									const char *filename);
int analyze_32bit_elf_solaris(Elf32_Ehdr *ehdr, void *map,
								const char *filename);
const char *get_symb_type_32_s(uint8_t info, Elf32_Sym sym,
								Elf32_Shdr *shdr);

#endif /* _HNM_ */
