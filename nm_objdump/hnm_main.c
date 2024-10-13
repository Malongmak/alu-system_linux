#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include "hnm.h"

/**
* analyze_file - Analyze an ELF file specified by filename.
*
* This function opens the file, maps it into memory, and analyzes it as either
* a 32-bit or 64-bit ELF file
* based on the ELF class. It then calls the appropriate analysis function for
* the ELF type.
*
* @filename: The name of the ELF file to analyze.
* Return: 0 on success, 1 on failure.
*/
int analyze_file(const char *filename)
{
	int fd;
	void *map;
	size_t file_size;
	Elf32_Ehdr *ehdr32;
	Elf64_Ehdr *ehdr64;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
	{
		perror("open");
		return (1);
	}

	file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	map = mmap(0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
	{
		perror("mmap");
		return (1);
	}
	ehdr32 = (Elf32_Ehdr *)map;
	ehdr64 = (Elf64_Ehdr *)map;
	if (ehdr32->e_ident[EI_CLASS] == ELFCLASS32)
	{
		if (ehdr32->e_ident[EI_OSABI] == ELFOSABI_SOLARIS)
			analyze_32bit_elf_solaris(ehdr32, map, filename);
		else
			analyze_32bit_elf(ehdr32, map, filename);
	}
	else if (ehdr64->e_ident[EI_CLASS] == ELFCLASS64)
		analyze_64bit_elf(ehdr64, map, filename);
	else
	{
		fprintf(stderr, "No es un archivo ELF válido.\n");
		return (1);
	}
	close(fd);
	munmap(map, file_size);
	return (0);
}

/**
* main - Entry point for the hnm program.
*
* This function processes command-line arguments to analyze one or more ELF
* files using the analyze_file function.
*
* @argc: The number of command-line arguments.
* @argv: An array of strings representing the command-line arguments.
* Return: 0 on success, 1 on failure.
*/
int main(int argc, char *argv[])
{
	int i;
	/* Check if there are at least 2 command-line arguments (incl Prog name)*/
	if (argc < 2)
	{
		fprintf(stderr, "hnm: %s [objfile...]\n", argv[0]);
		return (1);
	}
	/*Iterate through command-line arguments starting the second argument*/
	for (i = 1; i < argc; i++)
	{
		/* Call analyze_ function analyze the ELF file specified by argv[i]*/
		if (analyze_file(argv[i]) != 0)
		{
			return (1);
		}
	}

	return (0);
}
