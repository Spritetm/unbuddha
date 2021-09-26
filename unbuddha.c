#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "crc.h"
#include "cjson/cJSON.h"
#include <unistd.h>

uint32_t lfsr_state_init=0x84;
uint8_t xorval_init=0xef;
uint32_t lfsr_taps=0xe03e;
uint32_t lfsr_state;
uint8_t xorval;

int lfsr_bit=0;
uint64_t force_lfsr_output=0;

int gen_lfsr() {
	if (force_lfsr_output) {
		int bit=force_lfsr_output>>(lfsr_bit&63);
		lfsr_bit++;
		return bit&1;
	}
	lfsr_bit++;
#if 0
	//normal
	int newbit=(__builtin_popcount(lfsr_state&lfsr_taps)+1)&1;
	lfsr_state>>=1;
	lfsr_state|=(newbit<<15);
#else
	//Galois
	int newbit=lfsr_state&1;
	lfsr_state>>=1;
	if (newbit) lfsr_state^=lfsr_taps;
#endif
	return newbit;
}

void xorstream_reset() {
	lfsr_state=lfsr_state_init;
	xorval=xorval_init;
	lfsr_bit=0;
}

uint8_t xorstream_next() {
	uint8_t ret=xorval;
	int carry=(xorval&0x80)?1:0;
	xorval<<=1;
	if ((gen_lfsr()) ^ carry) xorval^=0x21;
	return ret;
}

void xor_crypt(void *buf, int len) {
	uint8_t *mem=(uint8_t *)buf;
	xorstream_reset();
	//Decrypt file entry header
	for (int i=0; i<len; i++) {
		mem[i]^=xorstream_next();
	}
}

typedef struct  __attribute__((packed)) {
	uint16_t ecrc;
	uint16_t dcrc;
	uint32_t first_free_byte; //address after the last file
	uint16_t dcrc2;           //same as dcrc. Note that fw actually checks *this* field.
	uint16_t fcrc;             //CRC over encrypted image range 0x800-0x10000
	uint32_t filecount;
	uint32_t unused[2];       //always 0xFFFFFFFF
	char magic[8];            //SH50N[0][0xff][0xff]
} file_entry_hdr_t;

typedef struct  __attribute__((packed)) {
	uint16_t ecrc;
	uint16_t dcrc;
	uint32_t offset;
	uint32_t length;
	uint32_t index;
	char filename[16];
} file_entry_t;

typedef struct  __attribute__((packed)) {
	uint16_t idx;
	uint16_t len;
	uint16_t unk1; //0, possibly part of len
	uint16_t load_at;
	uint16_t unk2; //0, possibly part of load_at
	uint16_t offset;
	uint16_t dcrc;
	uint16_t tcrc;
} code_idx_ent_t;


uint32_t val32(uint32_t v) {
	uint8_t *bv=(uint8_t*)&v;
	return (bv[0]<<24)|(bv[1]<<16)|(bv[2]<<8)|(bv[3]);
}

uint16_t val16(uint16_t v) {
	uint8_t *bv=(uint8_t*)&v;
	return (bv[0]<<8)|(bv[1]);
}

uint16_t toval16(uint16_t v) {
	uint16_t ret;
	uint8_t *bv=(uint8_t*)&ret;
	bv[0]=v>>8;
	bv[1]=v;
	return ret;
}

uint32_t toval32(uint32_t v) {
	uint32_t ret;
	uint8_t *bv=(uint8_t*)&ret;
	bv[0]=v>>24;
	bv[1]=v>>16;
	bv[2]=v>>8;
	bv[3]=v;
	return ret;
}


void check_crc(uint8_t *data, int len, uint16_t expected_crc, const char *desc) {
	uint16_t res=crc_ccitt_false(0, data, len);
	if (res!=expected_crc) {
		printf("CRC mismatch! Expected %04X calculated %04X in %s\n", expected_crc, res, desc);
	}
}

const char *out_dir="out/";

void code_decrypt(uint8_t *mem, int len, cJSON *json) {
	xorstream_reset();
	cJSON *json_chunks=cJSON_AddArrayToObject(json, "chunks");
	code_idx_ent_t *ent=(code_idx_ent_t*)mem;
	//decrypt first entity
	xor_crypt(mem, sizeof(code_idx_ent_t));
	//We assume that the first entry is the one with the highest index number, and that the
	//entries are labeled from 0 up to that.
	//Note: this assumption may be wrong, but I have no idea how to otherwise find the
	//number of indexes here...
	int no_entries=val16(ent[0].idx)+1;

	//decrypt other entries
	for (int i=1; i<no_entries; i++) {
		xor_crypt(&mem[i*sizeof(code_idx_ent_t)], sizeof(code_idx_ent_t));
	}

	for (int i=0; i<no_entries; i++) {
		check_crc((uint8_t*)&ent[i], sizeof(code_idx_ent_t)-2, val16(ent[i].tcrc), "code.app table entry crc");

		int len=val16(ent[i].len);
		int off=val16(ent[i].offset);
		
		char buf[256];
		sprintf(buf, "code-%04X.bin", val16(ent[i].idx));
		cJSON *json_chunk = cJSON_CreateObject();
		cJSON_AddStringToObject(json_chunk, "file", buf);
		cJSON_AddNumberToObject(json_chunk, "index", val16(ent[i].idx));
		cJSON_AddNumberToObject(json_chunk, "loadaddr", val16(ent[i].load_at));
		cJSON_AddItemToArray(json_chunks, json_chunk);

		xor_crypt(&mem[off], len);

		printf("code.app chunk idx 0x%02x offset 0x%04X len 0x%04X load at %04X\n", 
				val16(ent[i].idx), off, len, val16(ent[i].load_at));
		check_crc(&mem[off], len, val16(ent[i].dcrc), "code.app data chunk crc");

		sprintf(buf, "%s/code-%04X.bin", out_dir, val16(ent[i].idx));
		FILE *f=fopen(buf, "wb");
		fwrite(&mem[off], len, 1, f);
		fclose(f);
	}
}


void unbuddha(const char *filename) {
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

	cJSON *json = cJSON_CreateObject();
	cJSON_AddNumberToObject(json, "flash-size", filesize);
	cJSON_AddNumberToObject(json, "enc-xorval", xorval_init);
	cJSON_AddNumberToObject(json, "enc-lfsrtaps", lfsr_taps);
	cJSON_AddNumberToObject(json, "enc-lfsrstate", lfsr_state_init);

	cJSON *json_files = cJSON_AddArrayToObject(json, "files");

	//Decrypt file entry header
	xor_crypt(&mem[0], sizeof(file_entry_hdr_t));
	file_entry_hdr_t *fs_hdr=(file_entry_hdr_t *)&mem[0];

	//sanity check
	if (val32(fs_hdr->filecount)>256) {
		printf("Improbable amount of files %x. Wrong decryption parameters?\n", val32(fs_hdr->filecount));
		exit(1);
	}
	
	//check crcs
	check_crc(&mem[2], 30, val16(fs_hdr->ecrc), "file header ecrc");
	check_crc(&mem[32], 32*val32(fs_hdr->filecount), val16(fs_hdr->dcrc), "file index table crc");
	check_crc(&mem[0x800], 0xf800, val16(fs_hdr->fcrc), "flash range crc");

	cJSON *json_hdr = cJSON_CreateObject();
	cJSON_AddStringToObject(json_hdr, "magic", fs_hdr->magic);
	cJSON_AddItemToObject(json, "file-hdr", json_hdr);

	int filecount=val32(fs_hdr->filecount);
	
	//Decrypt file entries
	for (int i=0x20; i<(filecount+1)*sizeof(file_entry_hdr_t); i++) {
		if ((i&0x1F)==0) xorstream_reset();
		mem[i]^=xorstream_next();
	}
	file_entry_t *fs_ent=(file_entry_t *)&mem[0x20];
	for (int i=0; i<filecount; i++) {
		uint32_t off=val32(fs_ent[i].offset);
		uint32_t len=val32(fs_ent[i].length);
		if (off>filesize) {
			printf("File offset outside of file: 0x%X\n", off);
			exit(0);
		}
		if (off+len>filesize) {
			printf("File end outside of file: off 0x%X len 0x%X\n", off, len);
			exit(0);
		}
		//check crc on (encrypted) data
		check_crc(&mem[off], len, val16(fs_ent[i].dcrc), fs_ent[i].filename);
		printf("@%06X % 8d bytes %s\n", off, len, fs_ent[i].filename);
		if (off>filesize || off+len>filesize) {
			printf("Invalid offset/length %u/%u! Wrong decryption params?\n", off, len);
			continue;
		}
		cJSON *json_file=cJSON_CreateObject();
		cJSON_AddStringToObject(json_file, "filename", fs_ent[i].filename);
		cJSON_AddNumberToObject(json_file, "index", val32(fs_ent[i].index));
		cJSON_AddNumberToObject(json_file, "offset", off);
		cJSON_AddItemToArray(json_files, json_file);

		if (strcmp(fs_ent[i].filename, "code.app")==0) {
			cJSON *json_code_app=cJSON_CreateObject();
			code_decrypt(&mem[off], len, json_code_app);
			cJSON_AddItemToObject(json, "codeapp", json_code_app);
		} else {
#if 0
			//decrypt file?
			xor_crypt(&mem[off], len);
#endif
		}
		char buf[256];
		sprintf(buf, "%s/%s", out_dir, fs_ent[i].filename);
		FILE *of=fopen(buf, "wb");
		fwrite(&mem[off], len, 1, of);
		fclose(of);
	}

	//See if there is any 'loose' data at the end of the flash, save that as well.
	int pos=val32(fs_hdr->first_free_byte);
	while (pos<filesize && mem[pos]==0xff) pos++;
	if (pos<filesize) {
		pos=pos&~15; //round to 16-byte multiple
		cJSON_AddNumberToObject(json, "tail-data-offset", pos);
		cJSON_AddStringToObject(json, "tail-data-file", "tail-data.bin");
		char buf[256];
		sprintf(buf, "%s/tail-data.bin", out_dir);
		FILE *of=fopen(buf, "wb");
		fwrite(&mem[pos], filesize-pos, 1, of);
		fclose(of);
	}

	char buf[256];
	sprintf(buf, "%s/decoded-flash.bin", out_dir);
	FILE *of=fopen(buf, "wb");
	fwrite(mem, filesize, 1, of);
	fclose(of);

	sprintf(buf, "%s/layout.json", out_dir);
	of=fopen(buf, "w");
	char *json_txt = cJSON_Print(json);
	fwrite(json_txt, strlen(json_txt), 1, of);
	fclose(of);
}

cJSON *load_layout(const char *layout_file) {
	FILE *f=fopen(layout_file, "r");
	if (!f) {
		perror(layout_file);
		exit(1);
	}
	fseek(f, 0, SEEK_END);
	int len=ftell(f);
	rewind(f);
	char *txt=malloc(len);
	fread(txt, 1, len, f);
	fclose(f);
	cJSON *r=cJSON_ParseWithLength(txt, len);
	if (!r) {
		printf("Error parsing json at %s\n", cJSON_GetErrorPtr);
		exit(1);
	}
	free(txt);
	return r;
}

cJSON *jsonGetFromPath(cJSON *json, const char *path) {
	int i=0;
	while (path[i]!=0 && path[i]!='/') i++;
	char *pch=calloc(i+1, 1);
	strncpy(pch, path, i);
	json=cJSON_GetObjectItem(json, pch);
	free(pch);
	if (!json) return NULL;
	if (path[i]==0) return json;
	return jsonGetFromPath(json, &path[i+1]);
}

double jsonGetNumber(cJSON *json, const char *path) {
	cJSON *obj=jsonGetFromPath(json, path);
	if (!obj || !cJSON_IsNumber(obj)) {
		printf("%s: invalid or not a number\n", path);
		exit(1);
	}
	return cJSON_GetNumberValue(obj);
}

const char *jsonGetString(cJSON *json, const char *path) {
	cJSON *obj=jsonGetFromPath(json, path);
	if (!obj || !cJSON_IsString(obj)) {
		printf("%s: invalid or not a string\n", path);
		exit(1);
	}
	return cJSON_GetStringValue(obj);
}

cJSON *jsonGetObj(cJSON *json, const char *path) {
	cJSON *obj=jsonGetFromPath(json, path);
	if (!obj) {
		printf("%s: invalid\n", path);
		exit(1);
	}
	return obj;
}

int rebuddha_codeapp(uint8_t *mem, cJSON *json) {
	cJSON *chunks=jsonGetObj(json, "chunks");
	int chunk_ct=cJSON_GetArraySize(chunks);
	int pos=chunk_ct*sizeof(code_idx_ent_t);
	for (int i=0; i<chunk_ct; i++) {
		cJSON *chunk=cJSON_GetArrayItem(chunks, i);
		code_idx_ent_t *ent=(code_idx_ent_t*)&mem[i*sizeof(code_idx_ent_t)];
		memset(ent, 0, sizeof(*ent));
		ent->idx=toval16(jsonGetNumber(chunk, "index"));
		ent->load_at=toval16(jsonGetNumber(chunk, "loadaddr"));
		ent->offset=toval16(pos);
		FILE *f=fopen(jsonGetString(chunk, "file"), "rb");
		fseek(f, 0, SEEK_END);
		int len=ftell(f);
		rewind(f);
		fread(&mem[pos], len, 1, f);
		fclose(f);
		ent->dcrc=toval16(crc_ccitt_false(0, &mem[pos], len));
		xor_crypt(&mem[pos], len);
		ent->len=toval16(len);
		ent->tcrc=toval16(crc_ccitt_false(0, (uint8_t*)ent, sizeof(*ent)-2));
		xor_crypt(ent, sizeof(*ent));
		pos+=len;
	}
	printf("code.app: %d chunks, size 0x%X\n", chunk_ct, pos);
	return 0x7800;
//	return pos;
}

void rebuddha(const char *layout_file, FILE *out_file, int use_layout_offsets) {
	printf("Reconstituting flash image based on %s...\n", layout_file);
	cJSON *json=load_layout(layout_file);
	int mem_size=jsonGetNumber(json, "flash-size");
	uint8_t *mem=malloc(mem_size);
	memset(mem, 0xff, mem_size);

	//Set encryption params
	xorval_init=jsonGetNumber(json, "enc-xorval");
	lfsr_taps=jsonGetNumber(json, "enc-lfsrtaps");
	lfsr_state_init=jsonGetNumber(json, "enc-lfsrstate");
	xorstream_reset();
	
	//Place files in memory
	cJSON *files=jsonGetObj(json, "files");
	int file_ct=cJSON_GetArraySize(files);
	int file_pos=(file_ct*sizeof(file_entry_t))+sizeof(file_entry_hdr_t);
	for (int i=0; i<file_ct; i++) {
		cJSON *file=cJSON_GetArrayItem(files, i);
		if (use_layout_offsets) {
			file_pos=jsonGetNumber(file, "offset");
		} else {
			//round file_pos to next 2K offset
			file_pos=(file_pos+2047)&~2047;
		}
		file_entry_t *ent=(file_entry_t*)&mem[sizeof(file_entry_hdr_t)+sizeof(file_entry_t)*i];
		memset(ent, 0, sizeof(*ent));
		memset(ent->filename, 0xff, sizeof(ent->filename));
		strcpy(ent->filename, jsonGetString(file, "filename"));
		printf("@%08X: %s\n", file_pos, jsonGetString(file, "filename"));
		int filesize=0;
		//The routines here are supposed to put encrypted data into memory space.
		if (strcmp(ent->filename, "code.app")==0) {
			filesize=rebuddha_codeapp(&mem[file_pos], jsonGetObj(json, "codeapp"));
		} else {
			FILE *f=fopen(jsonGetString(file, "filename"), "rb");
			if (!f) {
				perror(jsonGetString(file, "filename"));
				exit(1);
			}
			fseek(f, 0, SEEK_END);
			filesize=ftell(f);
			rewind(f);
			fread(&mem[file_pos], filesize, 1, f);
			fclose(f);
		}
		ent->dcrc=toval16(crc_ccitt_false(0, &mem[file_pos], filesize));
		ent->offset=toval32(file_pos);
		ent->length=toval32(filesize);
		ent->index=toval32(jsonGetNumber(file, "index"));
		xor_crypt(ent, sizeof(*ent));
		file_pos+=filesize;
	}
	//write file header
	file_entry_hdr_t *ehdr=(file_entry_hdr_t*)&mem[0];
	memset(ehdr, 0, sizeof(*ehdr));
	ehdr->dcrc=toval16(crc_ccitt_false(0, &mem[32], 32*file_ct));
	ehdr->first_free_byte=toval32(file_pos);
	ehdr->dcrc2=ehdr->dcrc;
	ehdr->dcrc=0;
	uint16_t fcrc=crc_ccitt_false(0, &mem[0x800], 0xf800);
	ehdr->fcrc=toval16(fcrc);
	ehdr->filecount=toval32(file_ct);
	ehdr->unused[0]=0xffffffff;
	ehdr->unused[1]=0xffffffff;
	memset(ehdr->magic, 0xff, sizeof(ehdr->magic));
	strcpy(ehdr->magic, jsonGetString(json, "file-hdr/magic"));
	ehdr->ecrc=toval16(crc_ccitt_false(0, &mem[2], 30));
	//...and encrypt it
	xor_crypt(ehdr, sizeof(*ehdr));
	
	//Add tail data
	if (cJSON_HasObjectItem(json, "tail-data-offset")) {
		int offset=jsonGetNumber(json, "tail-data-offset");
		FILE *f=fopen(jsonGetString(json, "tail-data-file"), "rb");
		if (!f) {
			perror(jsonGetString(json, "tail-data-file"));
			exit(1);
		}
		fread(&mem[offset], 1, mem_size-offset, f);
		fclose(f);
	}

	//Write
	fwrite(mem, mem_size, 1, out_file);
}


int main(int argc, char **argv) {
	const char *filename="";
	int mode_un=0;
	int use_layout_offsets=0;
	const char *rebuddha_layout="";
	for (int i=1; i<argc; i++) {
		if (strcmp(argv[i], "-x")==0 && i<argc-1) {
			i++;
			xorval_init=strtol(argv[i], NULL, 0);
			mode_un=1;
		} else if (strcmp(argv[i], "-t")==0 && i<argc-1) {
			i++;
			lfsr_taps=strtol(argv[i], NULL, 0);
			mode_un=1;
		} else if (strcmp(argv[i], "-i")==0 && i<argc-1) {
			i++;
			lfsr_state_init=strtol(argv[i], NULL, 0);
			mode_un=1;
		} else if (strcmp(argv[i], "-o")==0 && i<argc-1) {
			i++;
			out_dir=argv[i];
			mode_un=1;
		} else if (strcmp(argv[i], "-F")==0 && i<argc-1) {
			i++;
			force_lfsr_output=strtoll(argv[i], NULL, 0);
		} else if (strcmp(argv[i], "-r")==0 && i<argc-1) {
			i++;
			rebuddha_layout=argv[i];
		} else if (strcmp(argv[i], "-l")==0) {
			use_layout_offsets=1;
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
	if (mode_un==1 && rebuddha_layout[0]!=0) {
		printf("Can't have rebuddha with unbuddha options!\n");
		filename="";
	}

	if (filename[0]==0) {
		printf("Usage: \n");
		printf("%s [-x xorval] [-t taps] [-i initial_state] [-o output_dir] flashdump.bin\n", argv[0]);
		printf("Splits and decrypts (where possible) a flash dump into separate files.\n");
		printf("%s [-l] -r dir/layout.json flash.bin\n", argv[0]);
		printf("Reconstitutes encrypted flash from a previous un-budda'd flash dump\n");
		printf("-l uses file offsets from layout, without this the offsets are auto-calculated\n");
		exit(0);
	}

	if (rebuddha_layout[0]!=0) {
		char *s=strdup(rebuddha_layout);
		char *layout_file;
		int i=strlen(s)-1;
		//We want to chdir() to the directory the layout file is in in order
		//to read all the components...
		while (i!=0 && s[i]!='/') i--;
		if (i==0) {
			layout_file=s;
		} else {
			s[i]=0;
			layout_file=&s[i+1];
		}
		//...but we want the output file to be in the current dir; open it before the chdir() call.
		FILE *of=fopen(filename, "wb");
		if (!of) {
			perror(filename);
			exit(1);
		}
		if (i!=0) {
			if (chdir(s)) {
				perror(s);
				exit(1);
			}
		}
		rebuddha(layout_file, of, use_layout_offsets);
		fclose(of);
	} else {
		unbuddha(filename);
	}
	return 0;
}