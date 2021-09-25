#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

uint32_t lfsr_state_init=0x84;
uint8_t xorval_init=0xef;
uint32_t lfsr_taps=0xe03e;
uint32_t lfsr_state;
uint8_t xorval;

int gen_lfsr() {
	int newbit=(__builtin_popcount(lfsr_state&lfsr_taps)+1)&1;
	lfsr_state>>=1;
	lfsr_state|=(newbit<<15);
	return newbit;
}

void xorstream_reset() {
	lfsr_state=lfsr_state_init;
	xorval=xorval_init;
}

uint8_t xorstream_next() {
	uint8_t ret=xorval;
	int carry=(xorval&0x80)?1:0;
	xorval<<=1;
	if ((gen_lfsr()) ^ carry) xorval^=0x21;
	return ret;
}

//From 0x20: file entry table

typedef struct  __attribute__((packed)) {
	uint32_t unk1[3];
	uint32_t filecount;
	uint32_t unused[2];
	char magic[8];
} file_entry_hdr_t;

typedef struct  __attribute__((packed)) {
	uint16_t ecrc;
	uint16_t dcrc;
	uint32_t offset;
	uint32_t length;
	uint32_t unk2;
	char filename[16];
} file_entry_t;

typedef struct  __attribute__((packed)) {
	uint16_t idx;
	uint16_t len;
	uint16_t unk1;
	uint16_t type;
	uint16_t unk2;
	uint16_t offset;
	uint32_t unk3;
} code_idx_ent_t;


uint32_t val32(uint32_t v) {
	uint8_t *bv=(uint8_t*)&v;
	return (bv[0]<<24)|(bv[1]<<16)|(bv[2]<<8)|(bv[3]);
}

uint16_t val16(uint16_t v) {
	uint8_t *bv=(uint8_t*)&v;
	return (bv[0]<<8)|(bv[1]);
}


const char *out_dir="out/";

void code_decrypt(uint8_t *mem, int len) {
	xorstream_reset();
	//decrypt entities
	code_idx_ent_t *ent=(code_idx_ent_t*)mem;
	for (int i=0; i<16*sizeof(code_idx_ent_t); i++) {
		if ((i&15)==0) xorstream_reset();
		mem[i]^=xorstream_next();
	}

	for (int i=0; i<16; i++) {
		int len=val16(ent[i].len);
		int off=val16(ent[i].offset);
		xorstream_reset();
		for (int j=0; j<len; j++) {
			mem[j+off]^=xorstream_next();
		}

		char buf[256];
		sprintf(buf, "%s/code-%04X.bin", out_dir, val16(ent[i].idx));
		FILE *f=fopen(buf, "wb");
		fwrite(&mem[off], len, 1, f);
		fclose(f);
	}
}

int main(int argc, char **argv) {
	const char *filename="";
	for (int i=1; i<argc; i++) {
		if (strcmp(argv[i], "-x")==0 && i<argc-1) {
			i++;
			xorval_init=strtol(argv[i], NULL, 0);
		} else if (strcmp(argv[i], "-t")==0 && i<argc-1) {
			i++;
			lfsr_taps=strtol(argv[i], NULL, 0);
		} else if (strcmp(argv[i], "-i")==0 && i<argc-1) {
			i++;
			lfsr_state_init=strtol(argv[i], NULL, 0);
		} else if (strcmp(argv[i], "-o")==0 && i<argc-1) {
			i++;
			out_dir=argv[i];
		} else if (strcmp(argv[i], "-h")==0) {
			filename="";
			break;
		} else {
			if (filename[0]==0) {
				filename=argv[i];
			} else {
				printf("Unrecognized arg %s\n", filename);
				filename="";
				break;
			}
		}
	}

	if (filename[0]==0) {
		printf("Usage: %s [-x xorval] [-t taps] [-i initial_state] [-o output_dir] flashdump.bin\n", argv[0]);
		exit(0);
	}

	mkdir(out_dir, 0777);

	FILE *f=fopen(filename, "rb");
	if (!f) {
		perror(filename);
		exit(1);
	}
	fseek(f, 0, SEEK_END);
	int filesize=ftell(f);
	fseek(f, 0, SEEK_SET);
	uint8_t *mem=calloc(filesize, 1);
	int rd=fread(mem, 1, filesize, f);
	if (rd!=filesize) {
		printf("Short read; only read %d/%d bytes\n", rd, filesize);
	}
	fclose(f);
	printf("Decrypting %s (%d KiB) to %s/ with parameters xorval 0x%02X taps 0x%04X initial_state 0x%04X\n",
			filename, filesize/1024, out_dir, xorval_init, lfsr_taps, lfsr_state_init);

#if 0
	uint64_t c;
	xorstream_reset();
	for (int i=0; i<64; i++) {
		c>>=1;
		if (gen_lfsr()) c|=(1ULL<<63ULL);
	}
	printf("LFSR generates keystream %llx\n", c);
	printf("XOR stream ");
	xorstream_reset();
	for (int i=0; i<16; i++) printf("%02X ", xorstream_next());
	printf(".\n");
#endif

	xorstream_reset();
	//Decrypt file entry header
	for (int i=0; i<sizeof(file_entry_hdr_t); i++) {
		mem[i]^=xorstream_next();
	}
	file_entry_hdr_t *fs_hdr=(file_entry_hdr_t *)&mem[0];
	if (val32(fs_hdr->filecount)>256) {
		printf("Improbable amount of files %x. Wrong decryption parameters?\n", val32(fs_hdr->filecount));
		fs_hdr->filecount=32<<24;
//		exit(1);
	}
	//Decrypt file entries
	for (int i=0x20; i<val32(fs_hdr->filecount)*sizeof(file_entry_hdr_t); i++) {
		if ((i&0x1F)==0) xorstream_reset();
		mem[i]^=xorstream_next();
//		putchar(mem[i]);
	}
	file_entry_t *fs_ent=(file_entry_t *)&mem[0x20];
	for (int i=0; i<val32(fs_hdr->filecount)-1; i++) {
		uint32_t off=val32(fs_ent[i].offset);
		uint32_t len=val32(fs_ent[i].length);
		printf("@%06X % 8d bytes %s\n", off, len, fs_ent[i].filename);
		if (off>filesize || off+len>filesize) {
			printf("Invalid offset/length %u/%u! Wrong decryption params?\n", off, len);
			continue;
		}
		if (strcmp(fs_ent[i].filename, "code.app")==0) {
			code_decrypt(&mem[off], len);
		} else {
			xorstream_reset();
			for (int i=off; i<off+len; i++) {
				mem[i]^=xorstream_next();
			}
		}
		char buf[256];
		sprintf(buf, "%s/%s", out_dir, fs_ent[i].filename);
		FILE *of=fopen(buf, "wb");
		fwrite(&mem[off], len, 1, of);
		fclose(of);
	}
}