# C Compiler
CC = gcc

# Compiler Flags
CFLAGS = -std=c90 -Wall -Werror -Wextra -pedantic
FILES_0 = hnm_main.c hnm_64.c hnm_32_big_endian.c hnm_32_little_endian.c hnm_32_solaris.c
FILES_1 = hobjdump.c hobjdump_utils.c hobjdump_32_bits.c hobjdump_64_bits.c

# Linker Flags (empty in this case)
LDFLAGS =

# Default Target: Build the hnm executable
all: hnm hobjdump

# Rule to build hnm
hnm: $(FILES_0)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
hobjdump: $(FILES_1)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# Target to clean generated files
clean:
	rm -rf hnm hobjdump

# Declaration of phony targets
.PHONY: all clean

