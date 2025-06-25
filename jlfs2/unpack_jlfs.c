#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "crc.h"
#include "hexdump.h"

/*
Based on the docs at https://kagaimiq.github.io/jielie/datafmt/jlfs.html
*/

typedef struct __attribute__((packed)) {
  uint16_t  hdr_crc;      /* Header CRC */
  uint16_t  burner_size;  /* Burner size */
  char      vid[4];       /* Version ID */
  uint32_t  flash_size;   /* Flash size */
  uint8_t   fs_ver;       /* FS version */
  uint8_t   block_align;  /* Block alignment */
  uint8_t   resvd;        /* (reserved) */
  uint8_t   special_opt;  /* Special option flag */
  char      pid[16];      /* Product ID */
}  jlfs2_flash_header_t;


typedef struct __attribute__((packed)) {
  uint16_t  hdr_crc;  /* Header CRC */
  uint16_t  data_crc; /* Data CRC */
  uint32_t  offset;   /* Data offset */
  uint32_t  size;     /* Size */
  uint8_t   attr;     /* Attributes */
  uint8_t   resvd;    /* (reserved) -- or not quite */
  uint16_t  index;    /* Index */
  char      name[16]; /* File name */
} jlfs2_file_entry_t;


typedef struct {
  uint16_t  hdr_crc;    /* Header CRC */
  uint16_t  list_crc;   /* File list CRC */
  uint32_t  info1;
  uint32_t  info2;
  uint32_t  count;      /* File count */
  uint32_t  version1;
  uint32_t  version2;
  uint8_t   chiptype[8];
} sydfs_hdr_t;

//Note this is an XOR operation, so encrypt == decrypt.
uint16_t jl_crypt(uint8_t *data, uint8_t *crypt_data, int len, uint16_t key) {
    while (len--) {
        *crypt_data++ = *data++ ^ key;
        key = (key << 1) ^ ((key >> 15) ? 0x1021 : 0);
    }
	return key;
}

int crc_valid(uint8_t *data, int len, uint16_t expected_crc, const char *desc) {
	uint16_t res=crc_ccitt_false(0, data, len);
	if (res!=expected_crc) {
		printf("CRC mismatch! Expected %04X calculated %04X in %s\n", expected_crc, res, desc);
	}
}

void apphdr_read_sect(FILE *f, int offset, uint8_t *buf, int key) {
	uint8_t enc[32];
	fseek(f, offset, SEEK_SET);
	fread(enc, 32, 1, f);
	jl_crypt(enc, buf, 32, key^(offset>>2));
}

void apphdr_read(FILE *f, int offset, int count, uint8_t *buf, int key) {
	uint8_t data[32];
	int r_off=offset&(~31);
	int p=0;
	//read 1st sector
	apphdr_read_sect(f, r_off, data, key);
	for (int i=offset-r_off; i<32; i++) {
		if (p<count) buf[p++]=data[i];
	}
	r_off+=32;
	for (; p<count; p++) {
		apphdr_read_sect(f, r_off, data, key);
		for (int i=0; i<32; i++) {
			if (p<count) buf[p++]=data[i];
		}
		r_off+=32;
	}
}

int check_jlfs2_entry(jlfs2_file_entry_t *dfhdr) {
	uint8_t *p=(uint8_t*)dfhdr;
	uint16_t crc=crc_ccitt_false(0, p+2, sizeof(jlfs2_file_entry_t)-2);
	if (crc!=dfhdr->hdr_crc) return 0;
	int found_zero=0;
	for (int i=0; i<16; i++) {
		if (dfhdr->name[i]>128) return 0;
		if (dfhdr->name[i]==0) {
			found_zero=1;
			break;
		}
	}
	if (!found_zero) return 0;
	return 1;
}

void print_file_info(int idx, jlfs2_file_entry_t *dfhdr) {
	printf("Idx %d: file %s size %x, type %d off %x idx %d attr ", idx, 
			dfhdr->name, dfhdr->size, dfhdr->attr&7, dfhdr->offset, dfhdr->index);
	if (dfhdr->attr&(1<<4)) printf("SPEC ");
	if (dfhdr->attr&(1<<5)) printf("unk ");
	if (dfhdr->attr&(1<<6)) printf("COMPR ");
	if (dfhdr->attr&(1<<7)) printf("ADH ");
	printf("\n");
}

int main(int argc, char **argv) {
	FILE *f=NULL;
	if (argc>1) f=fopen(argv[1], "rb");
	if (!f) {
		printf("Usage: %s file.bin\n", argv[0]);
		exit(1);
	}

	//Read general header
	jlfs2_flash_header_t header, htst;
	fread(&header, sizeof(header), 1, f);
	memcpy(&htst, &header, sizeof(header));

	jlfs2_file_entry_t fhdr, dfhdr;
	fread(&fhdr, sizeof(fhdr), 1, f);
	int key=0;
	int idx=0;
	while (key<65536) {
		jl_crypt((uint8_t*)&fhdr, (uint8_t*)&dfhdr, sizeof(fhdr), key);
		if (check_jlfs2_entry(&dfhdr)) {
			printf("Found key %04x file %s\n", key, dfhdr.name);
			break;
		}
		key++;
	}
	int app_dir_head_off=-1;
	int last_idx_nonzero=(dfhdr.index==0);
	while(1) {
		//Print info in dfhdr and ToDo: save file
		print_file_info(idx, &dfhdr);
		if (strcmp(dfhdr.name, "app_dir_head")==0) app_dir_head_off=dfhdr.offset;
		if (last_idx_nonzero) {
			if (dfhdr.index!=0) break;
		} else {
			if (dfhdr.index==0) break;
		}
		idx++;
		fread(&fhdr, sizeof(fhdr), 1, f);
		jl_crypt((uint8_t*)&fhdr, (uint8_t*)&dfhdr, sizeof(fhdr), key);
	}
	if (app_dir_head_off>=0) {
		printf("Decoding app_dir at %x\n", app_dir_head_off);
		jlfs2_file_entry_t ahdr;
		int akey=0;
		while (akey!=0x10000) {
			apphdr_read(f, app_dir_head_off, sizeof(jlfs2_file_entry_t), (uint8_t*)&ahdr, akey);
			if (check_jlfs2_entry(&ahdr)) {
				printf("App area key %x fn %s\n", akey, ahdr.name);
				break;
			}
			akey++;
		}
		idx=0;
		int off=app_dir_head_off;
		int next_off=0;
		while(1) {
			if (!check_jlfs2_entry(&ahdr)) {
				printf("Invalid file header. Ending.\n");
				break;
			}
			print_file_info(idx, &ahdr);
			if (idx==0) next_off=app_dir_head_off+ahdr.size;
			if (strncmp(ahdr.name, "dir_", 4)==0) {
				next_off=off+ahdr.offset;
			}
			idx++;
			if (last_idx_nonzero) {
				if (ahdr.index!=0) {
					off=next_off;
					idx=0;
				}
			} else {
				if (ahdr.index==0) {
					off=next_off;
					idx=0;
				}
			}
			printf("off %x\n", off+sizeof(jlfs2_file_entry_t)*idx);
			apphdr_read(f, off+sizeof(jlfs2_file_entry_t)*idx, sizeof(jlfs2_file_entry_t), (uint8_t*)&ahdr, akey);
			hexdump(&ahdr, 32);
		}


	FILE *of=fopen("dec.bin", "wb");
	int pos=app_dir_head_off;
	while(!feof(f)) {
		uint8_t data[32];
		apphdr_read(f, pos, 32, data, akey);
		fwrite(data, 32, 1, of);
		pos+=32;
	}
	}


}

