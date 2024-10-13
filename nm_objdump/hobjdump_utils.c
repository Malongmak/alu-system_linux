#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include "hobjdump.h"


/**
* print_flag - Print a flag if it is set in the flags variable.
*
* Function checks if a specific flag is set in the given flags variable and
* prints the corresponding flag name. It also maintains a flag_printed variable
* to handle the formatting of multiple flags.
*
* @flag_printed: A pointer to a flag indicating whether a flag has been printed
* If a flag has been printed, is set to 1; otherwise, it remains unchanged (0).
* @flags: The variable containing multiple flags.
* @flag: The specific flag to check in the flags variable.
* @flag_name: The name of the flag to print if it is set.
*/
void print_flag(int *flag_printed, unsigned long flags, unsigned long flag,
				const char *flag_name)
{
	if (flags & flag)
	{
		if (*flag_printed)
			printf(", ");
		printf("%s", flag_name);
		*flag_printed = 1;
	}
}

/**
* my_be32toh - Convert a 32-bit value between big-endian and host byte order.
*
* This function converts a 32-bit value between big-endian and host byte order
* If the specified endianness is big-endian, the function swaps the byte order;
* otherwise, it returns the value unchanged. The purpose is to ensure proper
* byte order conversion based on the endianness of the input data.
*
* @value: The 32-bit value to be converted.
* @is_big_endian: A flag indicating whether the input data is in big-endian
* format (1 for true, 0 for false).
* Return: The converted 32-bit value in host byte order.
*/
uint32_t my_be32toh(uint32_t value, int is_big_endian)
{
	if (is_big_endian)
		return (((value >> 24) & 0xFF) |
				((value >> 8) & 0xFF00) |
				((value & 0xFF00) << 8) |
				((value & 0xFF) << 24));
	else
		return (value);

}


/**
* my_be16toh - Convert a 16-bit value between big-endian and host byte order.
*
* This function converts a 16-bit value between big-endian and host byte order.
* If the specified endianness is big-endian, the function swaps the byte order;
* otherwise, it returns the value unchanged. The purpose is to ensure proper
* byte order conversion based on the endianness of the input data.
*
* @value: The 16-bit value to be converted.
* @is_big_endian: A flag indicating whether the input data is in big-endian
* format (1 for true, 0 for false).
* Return: The converted 16-bit value in host byte order.
*/
uint16_t my_be16toh(uint16_t value, int is_big_endian)
{
	if (is_big_endian)
		return (((value >> 8) & 0xFF) | ((value & 0xFF) << 8));
	else
		return (value);
}
