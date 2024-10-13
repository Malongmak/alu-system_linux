#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include "hnm.h"

/**
* byteswap32 - Swap the bytes of a 32-bit unsigned integer to change endianness
*
* This function reorders  bytes of a 32-bit unsigned integer from little-endian
* format big-endian format or vice versa.It is commonly used for data conversio
* between systems with different byte orderings.
*
* @value: The 32-bit unsigned integer whose bytes will be swapped.
* Return: The 32-bit unsigned integer with its bytes swapped.
*/
uint32_t byteswap32(uint32_t value)
{
	return (((value & 0x000000FF) << 24) |
		((value & 0x0000FF00) << 8) |
		((value & 0x00FF0000) >> 8) |
		((value & 0xFF000000) >> 24));
}

/**
* byteswap16 - Swap the bytes of a 16-bit unsigned integer to change endianness
*
* This function reorders the bytes of 6-bit unsigned integer from little-endian
* format big-endian format or vice versa.It is commonly used for data conversio
* between systems with different byte orderings.
*
* @value: The 16-bit unsigned integer whose bytes will be swapped.
* Return: The 16-bit unsigned integer with its bytes swapped.
*/
uint16_t byteswap16(uint16_t value)
{
	return (((value & 0x00FF) << 8) |
		((value & 0xFF00) >> 8));
}

/**
* process_symbols_32bit_big_endian - Process and display symbol information
* from a 32-bit big-endian ELF file.
*
* This function takes an ELF header, a memory map of the file, and the filename
* and extracts and displays
* symbol information from the ELF file. It locates the symbol table and string
* table sections, then iterates
* through the symbols, printing their type, name, and value if available.
*
* @ehdr: Pointer to the ELF header.
* @map: Pointer to the memory-mapped ELF file.
* @filename: The name of the ELF file.
*/
void process_symbols_32bit_big_endian(Elf32_Ehdr *ehdr, void *map,
										const char *filename)
{
	int i, num_symbols;
	Elf32_Sym *symtab;
	char *strtab_data;
	Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)map + byteswap32(ehdr->e_shoff));
	Elf32_Shdr *symtab_section = NULL;
	Elf32_Shdr *strtab_section = NULL;

	for (i = 0; i < byteswap16(ehdr->e_shnum); i++)
	{
		if (byteswap32(shdr[i].sh_type) == SHT_SYMTAB)
			symtab_section = &shdr[i];
		else if (byteswap32(shdr[i].sh_type) == SHT_STRTAB)
			strtab_section = &shdr[i];
	}

	if (!symtab_section || !strtab_section)
	{
		fprintf(stderr, "./hnm: %s: no symbols\n", filename);
		return;
	}
	/* Acceso a la tabla de símbolos y tabla de cadenas. */
	symtab = (Elf32_Sym *)((char *)map + byteswap32(symtab_section->sh_offset));
	strtab_data = (char *)((char *)map + byteswap32(strtab_section->sh_offset));
	num_symbols = byteswap32(symtab_section->sh_size) / sizeof(Elf32_Sym);
	/* Recorre los símbolos y muestra la información. */
	for (i = 0; i < num_symbols; i++)
	{
		if (byteswap32(symtab[i].st_name) != 0)
		{
			char *symbol_name = strtab_data + byteswap32(symtab[i].st_name);
			const char *symbol_type_str = get_symbol_type_32(symtab[i].st_info,
			symtab[i], shdr);

			if (symbol_type_str[0] != 'U')
				printf("%08x %s %s\n", byteswap32(symtab[i].st_value),
				symbol_type_str, symbol_name);
			else
				printf("         %s %s\n", symbol_type_str, symbol_name);
		}
	}
}

