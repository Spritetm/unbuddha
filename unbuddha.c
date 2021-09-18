#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t lfsr_state_init=0x84;
uint32_t lfsr_taps=0xe03e;
uint32_t lfsr_state;
uint8_t xorval=0xef;

int gen_lfsr() {
	int newbit=(__builtin_popcount(lfsr_state&lfsr_taps)+1)&1;
	lfsr_state>>=1;
	lfsr_state|=(newbit<<15);
	return newbit;
}

void xorstream_reset() {
	lfsr_state=lfsr_state_init;
	xorval=0xef;
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
	uint32_t unk1;
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
		sprintf(buf, "out/code/%04X.bin", val16(ent[i].idx));
		FILE *f=fopen(buf, "wb");
		fwrite(&mem[off], len, 1, f);
		fclose(f);
	}

}

int main(int argc, char *argv) {
#if 0
	uint64_t c;
	xorstream_reset();
	for (int i=0; i<64; i++) {
		c>>=1;
		if (gen_lfsr()) c|=(1ULL<<63ULL);
	}
	printf("%llx\n", c);
	exit(0);
#endif

	FILE *f=fopen("buddha.bin", "rb");
	uint8_t mem[2*1024*1024];
	fread(mem, sizeof(mem), 1, f);
	fclose(f);

	xorstream_reset();
	//Decrypt file entry header
	for (int i=0; i<sizeof(file_entry_hdr_t); i++) {
		mem[i]^=xorstream_next();
	}
	file_entry_hdr_t *fs_hdr=(file_entry_hdr_t *)&mem[0];
	//Decrypt file entries
	for (int i=0x20; i<val32(fs_hdr->filecount)*sizeof(file_entry_hdr_t); i++) {
		if ((i&0x1F)==0) xorstream_reset();
		mem[i]^=xorstream_next();
//		putchar(mem[i]);
	}
	file_entry_t *fs_ent=(file_entry_t *)&mem[0x20];
	for (int i=0; i<val32(fs_hdr->filecount)-1; i++) {
		int off=val32(fs_ent[i].offset);
		int len=val32(fs_ent[i].length);
		if (strcmp(fs_ent[i].filename, "code.app")==0) {
			code_decrypt(&mem[off], len);
		}
		printf("@%06X % 8d bytes %s\n", off, len, fs_ent[i].filename);
		char buf[256];
		sprintf(buf, "out/%s", fs_ent[i].filename);
		FILE *of=fopen(buf, "wb");
		fwrite(&mem[off], len, 1, of);
		fclose(of);
	}
}