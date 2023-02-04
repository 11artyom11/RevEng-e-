/**
 * @file main.c
 * @author Artyom Grigoryan (grigorianartyom1@gmail.com)
 * @brief This is a program to analyze ELF files
 * @version 0.1
 * @date 2023-02-04
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#define print_pair_string(NAME, VALUE) 			printf("%s\t <---> \t%s\n", NAME, VALUE);
#define print_pair_unsigned(NAME, VALUE) 		printf("%s\t <---> \t%u\n", NAME, VALUE);
#define print_pair_hex(NAME, VALUE) 			printf("%s\t <---> \t0x%x\n", NAME, VALUE);
#define print_pair_lhex(NAME, VALUE) 			printf("%s\t <---> \t0x%lx\n", NAME, VALUE);
#define print_pair_uarray(NAME, VALUE, LEN) 	printf("%s <---> ", NAME); \
												for (size_t i = 0; i < LEN; i++) { \
													printf(" 0x%x |", VALUE[i]); \
												} printf("\n");\


/**
 * @brief Load elf header to struct Elf64_Ehdr from FILE
 * 
 * @param[out] e_hdr output elf header struct where binary will be after import  
 * @param[in] path path of binary file to be put into elf64_ehdr struct
 * @param[in] path_len length of path of binary @path
 */
void 
load_elf64_header (Elf64_Ehdr* e_hdr, FILE* binfile){
	if (1 != fread(e_hdr, sizeof(Elf64_Ehdr), 1, binfile)){
		printf("Failed to put bin in header struct\n");
		exit(1);
	}	
	/* This check is optional */
	int elfvalid = memcmp(e_hdr->e_ident, ELFMAG, 4);
	//if elf magic is valid valid elf magic is \177ELF
	assert(elfvalid == 0);
}

/**
 * @brief Load elf64 program table to struct 
 * 
 * @param[out] p_hdr loadable program header
 * @param[in] e_hdr  elf header to get info about p_hdr location in binary
 * @param[in] binfile binary file to analyze and get header from 
 */
void load_elf64_phdr (Elf64_Phdr* p_hdr, const Elf64_Ehdr const* e_hdr, FILE* binfile)
{
	
}

/**
 * @brief Dump elf header structure in human-readable format
 * 
 * @param e_hdr header pointer to dump 
 */
void dump_elf64_header (Elf64_Ehdr* e_hdr)
{
	print_pair_uarray("Elf Magic", e_hdr->e_ident, EI_NIDENT); //print elf magic 16 bytes

/* Read architecture built 32/64 or unknown */
	switch (e_hdr->e_ident[EI_CLASS])
	{
	case ELFCLASS32:
		print_pair_string("Class", "32-bit");
		break;
	case ELFCLASS64:
		print_pair_string("Class", "64-bit");
		break;
	case ELFCLASSNONE:
	default:
		print_pair_string("Class", "UNKNOWN");
		break;
	}

/* Read endiannes */
	switch (e_hdr->e_ident[EI_DATA])
	{
	case ELFDATA2LSB:
		print_pair_string("Data", "little-endian");
		break;
	case ELFDATA2MSB:
		print_pair_string("Data", "big-endian");
		break;
	case ELFDATANONE:
	default:
		print_pair_string("Data", "unknown-endianness");
		break;
	}

/* Read version (if 1 then current and up to date) */
	switch (e_hdr->e_ident[EI_VERSION])
	{
	case 1:
		print_pair_string("Version", "1 (current)");
		break;
	default:
		print_pair_unsigned("Version", e_hdr->e_ident[EI_VERSION]);
		break;
	}

/* Read OS ABI */
	switch (e_hdr->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV			/* Alias.  */:
		print_pair_string("ABI", "System-V");
		break;
	case ELFOSABI_HPUX			/* HP-UX */:
		print_pair_string("ABI", " HP-UX");
		break;
	case ELFOSABI_NETBSD			/* NetBSD.  */:
		print_pair_string("ABI", "NetBSD");
		break;
	case ELFOSABI_GNU			/* Object uses GNU ELF extensions.  */:
		print_pair_string("ABI", "Object uses GNU ELF extensions.");
		break;
	case ELFOSABI_SOLARIS		/* Sun Solaris.  */:
		print_pair_string("ABI", "Sun Solaris");
		break;
	case ELFOSABI_AIX			/* IBM AIX.  */:
		print_pair_string("ABI", "IBM AIX");
		break;
	case ELFOSABI_IRIX		 	/* SGI Irix.  */:
		print_pair_string("ABI", "SGI Irix");
		break;
	case ELFOSABI_FREEBSD	 	/* FreeBSD.  */:
		print_pair_string("ABI", "FreeBSD");
		break;
	case ELFOSABI_TRU64			/* Compaq TRU64 UNIX.  */:
		print_pair_string("ABI", "Compaq TRU64 UNIX");
		break;
	case ELFOSABI_MODESTO	  	/* Novell Modesto.  */:
		print_pair_string("ABI", "Novell Modesto");
		break;
	case ELFOSABI_OPENBSD	   	/* OpenBSD.  */:
		print_pair_string("ABI", "OpenBSD");
		break;
	case 0xD					/* OpenVMS gogogo */:
		print_pair_string("ABI", "OpenVMS gogogo");
		break;
	case ELFOSABI_ARM_AEABI		/* ARM EABI */:
		print_pair_string("ABI", "ARM EABI");
		break;
	case ELFOSABI_ARM		  	/* ARM */:
		print_pair_string("ABI", "ARM");
		break;
	case ELFOSABI_STANDALONE		/* Standalone (embedded) application */:
		print_pair_string("ABI", "Standalone (embedded) application");
		break;
	default:
		print_pair_string("ABI", "Unknown ABI");
		break;
	}

/* Read ABI Version */
	print_pair_hex("ABI Version", e_hdr->e_ident[EI_ABIVERSION]);

	/* End of 16 byte magic */

/* Read type of binary */
	switch (e_hdr->e_type)
	{
	case ET_REL	/* Relocatable file */:
		print_pair_string("Type","Relocatable file")
		break;
	case ET_EXEC/* Executable file */:
		print_pair_string("Type","Executable file")
		break;
	case ET_DYN	/* Shared object file */:
		print_pair_string("Type","Shared object file")
		break;
	case ET_CORE/* Core file */:
		print_pair_string("Type","Core file")
		break;
	case ET_NUM	/* Number of defined types */:
		print_pair_string("Type","Number of defined types")
		break;
	case ET_LOOS/* OS-specific range start */:
		print_pair_string("Type","OS-specific range start")
		break;
	case ET_HIOS/* OS-specific range end */:
		print_pair_string("Type","OS-specific range end")
		break;
	case ET_LOPROC/* Processor-specific range start */:
		print_pair_string("Type","Processor-specific range start")
		break;
	case ET_HIPROC/* Processor-specific range end */:
		print_pair_string("Type","Processor-specific range end")
		break;
	case ET_NONE/* No file type */:
	default:
		print_pair_string("Type","No file type")
		break;
	}

/* Read machine type TODO: add non-hex strings */
	print_pair_hex("Machine", e_hdr->e_machine);
/* Read version of elf */
	print_pair_hex("Version", e_hdr->e_version);
/* Read program entry offset */
	print_pair_lhex("Entry point address" ,e_hdr->e_entry);
/* Read program header offset Usually 0x34 (for 32-bit) and 0x40 (for 64-bit)*/
	print_pair_lhex("Start of program header", e_hdr->e_phoff);
/* Read section header offset*/
	print_pair_lhex("Start of section header", e_hdr->e_shoff);
/* Read e_flags, purpose depends on architecture */
	print_pair_unsigned("Flags", e_hdr->e_flags);
/* Read size of this header */
	print_pair_unsigned("Size of this header", e_hdr->e_ehsize);
/* Read size of program header entry*/
	print_pair_unsigned("Size of program header entry", e_hdr->e_phentsize);
/* Read number of entries in program header table*/
	print_pair_unsigned("Number of entries in program header table", e_hdr->e_phnum);
/* Read size of section header entry*/
	print_pair_unsigned("Size of section header entry", e_hdr->e_shentsize);
/* Read number of entries in section header table */
	print_pair_unsigned("Number of entries in section header table", e_hdr->e_shnum);
/* Read number of section which contains section names */
	print_pair_unsigned("Section header string table index", e_hdr->e_shstrndx);
/* End of reading of elf header */
return;
}


int 
main(){
	FILE* binfile;
	Elf64_Ehdr hdr;
	const char path[] = "./a.out";
	char str[4] = {0};
	
	binfile = fopen(path, "rb");
	assert(binfile != NULL);

	load_elf64_header(&hdr, binfile);
	dump_elf64_header(&hdr);

	fclose(binfile);
	return 0;
}
