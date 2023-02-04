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
#include <unistd.h>

#define print_pair_string(NAME, VALUE) 			printf("%s----\t\t-----%s\n", NAME, VALUE);
#define print_pair_unsigned(NAME, VALUE) 		printf("%s----\t\t-----%u\n", NAME, VALUE);
#define print_pair_hex(NAME, VALUE) 			printf("%s----\t\t-----0x%x\n", NAME, VALUE);
#define print_pair_lhex(NAME, VALUE) 			printf("%s----\t\t-----0x%lx\n", NAME, VALUE);
#define print_pair_uarray(NAME, VALUE, LEN) 	printf("%s-----", NAME); \
												for (size_t i = 0; i < LEN; i++) { \
													printf(" 0x%x |", VALUE[i]); \
												} printf("\n");\

/**
 * @brief Free allocated array of program header array
 * 
 * @param phdr_arr_ptr pointer to array
 */
void free_phdr (Elf64_Phdr** phdr_arr_ptr){
	free(*phdr_arr_ptr);
	phdr_arr_ptr = NULL;
	assert(phdr_arr_ptr == NULL);
}


/**
 * @brief Load elf header to struct Elf64_Ehdr from FILE
 * 
 * @param[out] e_hdr Output elf header struct where binary will be after import  
 * @param[in] path Path of binary file to be put into elf64_ehdr struct
 * @param[in] path_len Length of path of binary @path
 */
void 
load_elf64_header (Elf64_Ehdr* e_hdr, FILE* binfile){
	if (1 != fread(e_hdr, sizeof(Elf64_Ehdr), 1, binfile)){
		printf("Failed to read elf header\n");
		exit(1);
	}	
	/* This check is optional */
	int elfvalid = memcmp(e_hdr->e_ident, ELFMAG, 4);
	//if elf magic is valid valid elf magic is \177ELF
	assert(elfvalid == 0);
}

/**
 * @brief Load elf64 program table to struct 
 * @attention This function allocates memory for p_hdr array
 * 			  please free it with according function 
 * 
 * @param[out] p_hdr Loadable program header
 * @param[in] e_hdr  Blf header to get info about p_hdr location in binary
 * @param[in] binfile Binary file to analyze and get header from 
 */
void
load_elf64_phdr (Elf64_Phdr** p_hdrs, const Elf64_Ehdr * e_hdr, FILE* binfile){
	assert (binfile != NULL);
	assert (e_hdr != NULL);
	
	/* Allocate memory for prgram headers */
	*p_hdrs = (Elf64_Phdr*)malloc(sizeof(Elf64_Phdr) * e_hdr->e_phnum);

	/* 
	We need to seek file pointer to program header offset, 
	as we cannot be sure that file pointer points to program header entry address
	*/
	lseek(fileno(binfile), e_hdr->e_phoff, SEEK_SET);

	/* Read from given offset into program header struct */
	if (1 != fread(*p_hdrs, sizeof(Elf64_Phdr), e_hdr->e_phnum, binfile)){
		printf("Failed to read program header\n");
	}
	return;
}

/**
 * @brief Dump elf header structure in human-readable format
 * 
 * @param e_hdr Header pointer to dump 
 */
void 
dump_elf64_header (const Elf64_Ehdr* e_hdr){
	printf("\n\n#####################################___ELF__FILE___HEADER____#####################################\n\n");
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

/**
 * @brief Dump single program header in human-readabe format
 * 
 * @param p_hdr Program header to dump
 */
void 
dump_elf64_program_header (const Elf64_Phdr* p_hdr){
	switch (p_hdr->p_type)
	{
	case PT_LOAD:
		print_pair_string("Type", "Loadable segment. ");
		break;
	case PT_DYNAMIC:
		print_pair_string("Type", "Dynamic linking information. ");
		break;
	case PT_INTERP:
		print_pair_string("Type", "Interpreter information. ");
		break;
	case PT_NOTE:
		print_pair_string("Type", "Auxiliary information. ");
		break;
	case PT_SHLIB:
		print_pair_string("Type", "Reserved");
		break;
	case PT_PHDR:
		print_pair_string("Type", "Program header itself. ");
		break;
	case PT_TLS:
		print_pair_string("Type", "Thread-Local Storage template. ");
		break;
	case PT_LOOS:
	case PT_HIOS:
		print_pair_string("Type", "Reserved inclusive range. Operating system specific. ");
		break;
	case PT_LOPROC:
	case PT_HIPROC:
		print_pair_string("Type", "Reserved inclusive range. Processor specific. ");
		break;
	case PT_NULL:
	default:
		print_pair_string("Type", "Program header table entry unused. ");
		break;
	}
	print_pair_hex("Flags", p_hdr->p_flags);
	print_pair_lhex("Offset", p_hdr->p_offset);
	print_pair_lhex("ViAddress", p_hdr->p_vaddr);
	print_pair_lhex("PhAddress", p_hdr->p_paddr);
	print_pair_lhex("FileSize", p_hdr->p_filesz);
	print_pair_lhex("MemSize", p_hdr->p_memsz);
	print_pair_lhex("Alignment", p_hdr->p_align);

	return;
}

/**
 * @brief Dump N program headers in human-readable format
 * 
 * @param p_hdr_arr Array of program header structs to dump
 * @param n Size of passed array
 */
void
dump_elf64_program_header_n (const Elf64_Phdr* p_hdr_arr, size_t n){
	printf("\n\n#################################___PROGRAM___HEADER___TABLE___####################################\n\n");
	for (size_t i = 0; i < n; i++){
		printf("\n--------------------------------------------%d---\n", i);
		dump_elf64_program_header(&p_hdr_arr[i]);
	}
}

int 
main(){
	FILE* binfile;
	Elf64_Ehdr e_hdr;
	Elf64_Phdr* p_hdrs;
	const char path[] = "./a.out";
	
	binfile = fopen(path, "rb");
	assert(binfile != NULL);

	load_elf64_header(&e_hdr, binfile);
	dump_elf64_header(&e_hdr);

	load_elf64_phdr(&p_hdrs, &e_hdr, binfile);
	dump_elf64_program_header_n(p_hdrs, e_hdr.e_phnum);

	free_phdr(&p_hdrs);
	fclose(binfile);
	return 0;
}


