#ifndef _HOBJDUMP_
#define _HOBJDUMP_

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>


#define HAS_SYMS 0x10
#define D_PAGED 0x100
#define EXEC_P 0x02
#define HAS_RELOC 0x01
#define DYNAMIC 0x40


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

int analyze_file(const char *filename);



/* utils */
void print_flag(int *flag_printed, unsigned long flags, unsigned long flag,
				const char *flag_name);
uint16_t my_be16toh(uint16_t value, int is_big_endian);
uint32_t my_be32toh(uint32_t value, int is_big_endian);

/* 32bit */
int analyze_32bit_elf(Elf32_Ehdr *ehdr, const char *filename, void *map);
void print_elf_header_32(Elf32_Ehdr *ehdr, const char *filename, void *map);
void print_sections_32(Elf32_Ehdr *ehdr, int is_big_endian, void *map);
void print_section_contents_32(Elf32_Shdr *shdr, char *map, int is_big_endian);
void print_hex_ascii_block_32(const Elf32_Shdr *shdr,
								const unsigned char *data, size_t offset,
								size_t size, int is_big_endian);

/* 64bit */
void print_elf_header_64(Elf64_Ehdr *ehdr, const char *filename, void *map);
int analyze_64bit_elf(Elf64_Ehdr *ehdr, const char *filename, void *map);
void print_sections_64(Elf64_Ehdr *ehdr, int is_big_endian, void *map);
void print_section_contents_64(Elf64_Shdr *shdr, char *map, int is_big_endian);
void print_hex_ascii_block(Elf64_Shdr *shdr, const unsigned char *data,
							size_t offset, size_t size, int is_big_endian);


#endif /* _HOBJDUMP_ */
