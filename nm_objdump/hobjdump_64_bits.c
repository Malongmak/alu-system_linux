#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include "hobjdump.h"


/**
* print_hex_ascii_block - Print a block of data in hexadecimal and ASCII format
*
* This function prints a block of data in both hexadecimal and ASCII format.
* It prints the memory address, hexadecimal values, and corresponding ASCII
* characters for each line.
*
* @shdr: A pointer to the ELF section header structure.
* @data: A pointer to the data to be printed.
* @offset: The offset within the data.
* @size: The size of the data to be printed.
* @is_big_endian: A flag indicating whether the ELF file is big-endian.
*/
void print_hex_ascii_block(Elf64_Shdr *shdr, const unsigned char *data,
							size_t offset, size_t size, int is_big_endian)
{
	size_t i, j;
	int max_digits = 4;
	char temp_buffer[16];

	for (i = 0; i < size; i += 16)
	{
		int current_digits = 0;
		unsigned long temp_addr = my_be32toh(shdr->sh_addr, is_big_endian) + i;

		current_digits = sprintf(temp_buffer, "%lx", temp_addr);
		if (current_digits > max_digits)
			max_digits = current_digits;
	}
	for (i = 0; i < size; i += 16)
	{
		printf(" %0*x", max_digits, (int)(my_be32toh(shdr->sh_addr,
			is_big_endian) + offset + i));
		for (j = 0; j < 16; j++)
		{
			if (j % 4 == 0)
				printf(" ");
			if (i + j < size)
				printf("%02x", data[offset + i + j]);
			else
				printf("  ");
		}
		printf("  ");
		for (j = 0; j < 16; j++)
		{
			if (i + j < size)
			{
				char c = data[offset + i + j];

				printf("%c", (c >= 32 && c <= 126) ? c : '.');
			}
			else
				printf(" ");
		}
		printf("\n");
	}
}

/**
* print_section_contents_64 - Print contents of a 64-bit ELF section.
*
* This function prints the contents of a 64-bit ELF section in both hexadecimal
* and ASCII format.
*
* @shdr: A pointer to the 64-bit ELF section header structure.
* @map: A pointer to the memory-mapped ELF file.
* @is_big_endian: A flag indicating whether the ELF file is big-endian.
*/
void print_section_contents_64(Elf64_Shdr *shdr, char *map, int is_big_endian)
{
	unsigned char *section_data = (unsigned char *)(map +
	my_be32toh(shdr->sh_offset, is_big_endian));
	size_t section_size = my_be32toh(shdr->sh_size, is_big_endian);

	print_hex_ascii_block(shdr, section_data, 0, section_size, is_big_endian);
}



/**
* print_sections_64 - Print contents of sections from a 64-bit ELF file.
*
* This function prints the contents of sections from a 64-bit ELF file,
* excluding specific sections. It iterates through the section headers and
* prints the contents of each section.
*
* @ehdr: A pointer to the 64-bit ELF header structure.
* @is_big_endian: A flag indicating whether the ELF file is big-endian.
* @map: A pointer to the memory-mapped ELF file.
*/
void print_sections_64(Elf64_Ehdr *ehdr, int is_big_endian, void *map)
{
	int i;
	size_t section_size;
	Elf64_Shdr *current_section;

	Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)map +
	my_be32toh(ehdr->e_shoff, is_big_endian));
	char *string_table = (char *)map +
	my_be32toh(shdr[my_be16toh(ehdr->e_shstrndx, is_big_endian)].sh_offset,
	is_big_endian);

	for (i = 1; i < my_be16toh(ehdr->e_shnum, is_big_endian); i++)
	{

		char *section_name = string_table + my_be32toh(shdr[i].sh_name,
		is_big_endian);

		/* Evita estas secciones */
		if (strcmp(section_name, ".bss") == 0 ||
			strcmp(section_name, ".shstrtab") == 0 ||
			strcmp(section_name, ".symtab") == 0 ||
			strcmp(section_name, ".tm_clone_table") == 0 ||/* solaris */
			strcmp(section_name, ".rel.text") == 0 ||
			strcmp(section_name, ".rel.data") == 0 ||
			strcmp(section_name, ".rela.eh_frame") == 0 ||
			strncmp(section_name, ".rela.debug", 11) == 0 ||
			strcmp(section_name, ".rela.text.startup") == 0 ||
			strcmp(section_name, ".strtab") == 0)
			{
			continue;
			}
		current_section = &shdr[i];
		section_size = current_section->sh_size;
		if (section_size > 0)
		{
			printf("Contents of section %s:\n", section_name);
			print_section_contents_64(&shdr[i], map, is_big_endian);
		}
	}
}

/**
* print_elf_header_64 - Print information from a 64-bit ELF header.
*
* This function prints various information from a 64-bit ELF header, including
* file format, architecture, flags, and start address.
*
* @ehdr: A pointer to the 64-bit ELF header structure.
* @filename: The name of the ELF file.
* @map: A pointer to the memory-mapped ELF file.
*/
void print_elf_header_64(Elf64_Ehdr *ehdr, const char *filename, void *map)
{
	const char *formatted_filename = filename;
	int flag_printed = 0;
	unsigned long flags_interp = 0;
	int is_big_endian = 0;

	if (formatted_filename[0] == '.' && formatted_filename[1] == '/')
		formatted_filename += 2;

	is_big_endian = (ehdr->e_ident[EI_DATA] == ELFDATA2MSB);
	printf("%s:     file format elf64-x86-64\n", formatted_filename);
	printf("architecture: i386:x86-64,");

	if (my_be16toh(ehdr->e_type, is_big_endian) == ET_EXEC)
		flags_interp |= EXEC_P;
	if (my_be16toh(ehdr->e_type, is_big_endian) == ET_REL)
		flags_interp |= HAS_RELOC;
	if (my_be16toh(ehdr->e_type, is_big_endian) == ET_DYN)
		flags_interp |= DYNAMIC;

	flags_interp |= (ehdr->e_shnum > 0) ? HAS_SYMS : 0;
	flags_interp |= (ehdr->e_phnum > 0) ? D_PAGED : 0;

	printf(" flags 0x%08lx:\n", flags_interp);

	print_flag(&flag_printed, flags_interp, EXEC_P, "EXEC_P");
	print_flag(&flag_printed, flags_interp, HAS_RELOC, "HAS_RELOC");
	print_flag(&flag_printed, flags_interp, HAS_SYMS, "HAS_SYMS");
	print_flag(&flag_printed, flags_interp, DYNAMIC, "DYNAMIC");
	print_flag(&flag_printed, flags_interp, D_PAGED, "D_PAGED");

	printf("\n");

	printf("start address 0x%016lx\n", (unsigned long)ehdr->e_entry);
	printf("\n");
	print_sections_64(ehdr, is_big_endian, map);
}


/**
* analyze_64bit_elf - Analyze and process a 32-bit ELF file.
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
int analyze_64bit_elf(Elf64_Ehdr *ehdr, const char *filename, void *map)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
	{
		printf("\n");
		print_elf_header_64(ehdr, filename, map);
	}
	else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
	{
		printf("\n");
		print_elf_header_64(ehdr, filename, map);
	}
	else
	{
		printf("endianness unknown.\n");
	}

	return (0);
}
