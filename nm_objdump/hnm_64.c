#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include "hnm.h"

/**
* get_symbol_type_64 - Get the type of a symbol in a 64-bit ELF file.
*
* This function takes the symbol information, the symbol itself, and an array
* of ELF section headers,
* and determines the type of the symbol. It returns a string representation of
* the symbol's type.
*
* @info: Information about the symbol.
* @sym: The symbol to analyze.
* @shdr: An array of ELF section headers.
* Return: A string representing the symbol's type.
*/
const char *get_symbol_type_64(uint8_t info, Elf64_Sym sym, Elf64_Shdr *shdr)
{
	if (ELF64_ST_BIND(info) == STB_GNU_UNIQUE)
		return ("u");
	if (ELF64_ST_BIND(info) == STB_WEAK && ELF64_ST_TYPE(info) == STT_OBJECT)
		return ((sym.st_shndx == SHN_UNDEF) ? "v" : "V");
	if (ELF64_ST_BIND(info) == STB_WEAK)
		return ((sym.st_shndx == SHN_UNDEF) ? "w" : "W");
	else if (sym.st_shndx == SHN_UNDEF)
		return ("U");
	else if (sym.st_shndx == SHN_ABS)
		return ("A");
	else if (sym.st_shndx == SHN_COMMON)
		return ("C");
	else if (shdr[sym.st_shndx].sh_type == SHT_NOBITS &&
			shdr[sym.st_shndx].sh_flags == (SHF_ALLOC | SHF_WRITE))
		return ((ELF64_ST_BIND(info) == STB_GLOBAL) ? "B" : "b");
	else if (shdr[sym.st_shndx].sh_type == SHT_PROGBITS &&
			shdr[sym.st_shndx].sh_flags == SHF_ALLOC)
		return ((ELF64_ST_BIND(info) == STB_GLOBAL) ? "R" : "r");
	else if (shdr[sym.st_shndx].sh_type == SHT_PROGBITS &&
			shdr[sym.st_shndx].sh_flags == (SHF_ALLOC | SHF_WRITE))
	return ((ELF64_ST_BIND(info) == STB_GLOBAL) ? "D" : "d");
	else if (shdr[sym.st_shndx].sh_type == SHT_PROGBITS &&
			shdr[sym.st_shndx].sh_flags == (SHF_ALLOC | SHF_EXECINSTR))
	return ((ELF64_ST_BIND(info) == STB_GLOBAL) ? "T" : "t");
	else if (shdr[sym.st_shndx].sh_type == SHT_DYNAMIC)
		return ("d");
	else
		return ("t");
}

/**
* process_symbols_64bit - DEisplay symbol information from a 64-bit ELF file.
*
* This function takes an ELF header, a memory map of the file, and the filename
* and extracts and displays
* symbol information from the ELF file. It locates the symbol table and string
* table sections, then iterates
*
* @ehdr: Pointer to the ELF header.
* @map: Pointer to the memory-mapped ELF file.
* @filename: The name of the ELF file.
*/
void process_symbols_64bit(Elf64_Ehdr *ehdr, void *map, const char *filename)
{
	int i, num_symbols;
	Elf64_Sym *symtab;
	char *strtab_data;
	Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)map + ehdr->e_shoff);
	Elf64_Shdr *symtab_section = NULL;
	Elf64_Shdr *strtab_section = NULL;

	for (i = 0; i < ehdr->e_shnum; i++)
	{
		if (shdr[i].sh_type == SHT_SYMTAB)
			symtab_section = &shdr[i];
		else if (shdr[i].sh_type == SHT_STRTAB)
			strtab_section = &shdr[i];
	}

	if (!symtab_section || !strtab_section)
	{
		fprintf(stderr, "./hnm: %s: no symbols\n", filename);
		return;
	}
	symtab = (Elf64_Sym *)((char *)map + symtab_section->sh_offset);
	strtab_data = (char *)((char *)map + strtab_section->sh_offset);
	num_symbols = symtab_section->sh_size / sizeof(Elf64_Sym);
	for (i = 0; i < num_symbols; i++)
	{
		char *symbol_name = strtab_data + symtab[i].st_name;

		if (strstr(symbol_name, ".c") != NULL)
			continue;
		if (symtab[i].st_name)
		{
			const char *symbol_type_str = get_symbol_type_64(symtab[i].st_info,
			symtab[i], shdr);
			if (symbol_type_str[0] != 'U' && symbol_type_str[0] != 'w')
				printf("%16.16lx %s %s\n", symtab[i].st_value, symbol_type_str,
				symbol_name);
			else
				printf("                 %s %s\n", symbol_type_str, symbol_name);
		}
	}
}

/**
* analyze_64bit_elf - Analyze and process a 64-bit ELF file.
*
* This function analyzes a 32-bit ELF header and its endianness, and then
* processes the symbols in the ELF file.
* Depending on the endianness of the file, it calls the appropriate function
* to process and display symbol information.
*
* @ehdr: Pointer to the ELF header.
* @map: Pointer to the memory-mapped ELF file.
* @filename: The name of the ELF file.
* Return: 0 on success.
*/
int analyze_64bit_elf(Elf64_Ehdr *ehdr, void *map, const char *filename)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
	{
		/* printf("little-endian.\n"); */
		process_symbols_64bit(ehdr, map, filename);

	}
	else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
	{
		printf("big-endian.\n");
	}
	else
	{
		printf("endianness unknown.\n");
	}

	return (0);
}
