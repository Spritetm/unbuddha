#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


int check_lfsr(uint32_t state, uint32_t taps, int len, uint64_t tst) {
	for (int i=0; i<len; i++) {
		int newbit=(__builtin_popcount(state&taps)+1)&1;
		state>>=1;
		state|=(newbit<<15);
		if (newbit != (tst&1)) return 0;
		tst>>=1ULL;
	}
	return 1;
}

uint8_t xorstream_next(uint8_t *xorval, uint8_t xorchg, int lfsr_bit) {
	uint8_t ret=*xorval;
	int carry=(*xorval&0x80)?1:0;
	*xorval<<=1;
	lfsr_bit=(lfsr_bit?1:0);
	if (lfsr_bit ^ carry) *xorval^=xorchg;
	return ret;
}

const char fat_allowed[]=
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	"abcdefghijklmnopqrstuvwxyz" \
	"$%-_@~`!(){}^#& .";

int check_valid_file_desc(uint8_t *desc, int byte) {
	if (byte==0 || byte==1 || byte==4 || byte==5 || byte==8 || byte==9 || byte==12 || byte==13 || byte==14) {
		//these bytes are expected to be 0
		if (desc[byte]!=0) return 0;
	}
	if (byte>=16) { //filename section
		if (desc[byte] == 0xff) {
			//If 0xff, the prev byte is 0 or 0xff.
			if (desc[byte-1]!=0 && desc[byte-1]!=0xff) return 0;
		} else if (desc[byte] == 0) {
			//Cannot follow a 0 or 0xff.
			if (desc[byte-1]==0 || desc[byte-1]==0xff) return 0;
			//End of file. Scan filename to see if we have exactly one period.
			int period_found=0;
			for (int i=16; i<byte; i++) {
				if (desc[i]=='.') period_found++;
			}
			if (period_found!=1) return 0;
		} else {
			//Character. These must not be after a 0 or 0xff.
			if (byte>16) {
				if (desc[byte-1]==0 || desc[byte-1]==0xff) return 0;
			}
			//They also should be allowed as a fat char.
			int is_allowed=0;
			const char *p=fat_allowed;
			while(*p!=0) {
				if (*p==desc[byte]) {
					is_allowed=1;
					break;
				}
				p++;
			}
			if (!is_allowed) return 0;
		}
	}
	return 1;
}

int find_lfsr_for(uint64_t keystr, int len) {
	for (int i=0; i<65536; i++) {
		for (int j=0; j<65536; j++) {
			if (check_lfsr(i, j, len, keystr)) {
				printf("Found LFSR: initial state 0x%x, taps 0x%x\n", i, j);
			}
		}
	}
}


void find_valid_lfsr_output_for_byte(uint8_t *enc, uint8_t *dec, int byte, int xorval, int xorchg, uint8_t *keystream) {
	//end condition
	if (byte==32) {
		uint64_t keystr=0;
		for (int i=0; i<32; i++) {
			if (keystream[i]) keystr|=(1<<i);
		}
		printf("Found lfsr keystream! %016LX Finding possible LFSR config...\n",keystr);
		find_lfsr_for(keystr, 30);
		return;
	}

	//Decode assuming a 0 LFSR output
	uint8_t xorval_lfsr_zero=xorval;
	dec[byte]=enc[byte]^xorstream_next(&xorval_lfsr_zero, xorchg, 0);
	if (check_valid_file_desc(dec, byte)) {
		keystream[byte]=0;
		find_valid_lfsr_output_for_byte(enc, dec, byte+1, xorval_lfsr_zero, xorchg, keystream);
	}

	//Decode assuming a 1 LFSR output
	uint8_t xorval_lfsr_one=xorval;
	dec[byte]=enc[byte]^xorstream_next(&xorval_lfsr_one, xorchg, 1);
	if (check_valid_file_desc(dec, byte)) {
		keystream[byte]=1;
		find_valid_lfsr_output_for_byte(enc, dec, byte+1, xorval_lfsr_one, xorchg, keystream);
	}
}



#define NO_FILE_ENTS 8 //assume there are at least this many files

int main(int argc, char **argv) {
	uint8_t testvector[32]={
		0x00, 0x00, 0xc7, 0x3c, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x63, 0x6f, 0x64, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	for (int i=0; i<32; i++) {
		if (!check_valid_file_desc(testvector, i)) {
			printf("Test: didn't like byte %d\n", i);
		}
	}


	FILE *f=fopen(argv[1], "r");
	if (!f) {
		perror(argv[1]);
		exit(1);
	}
	uint8_t fe[NO_FILE_ENTS*0x20];
	fread(&fe, 0x20, NO_FILE_ENTS, f);
	
	uint8_t *firstfe=&fe[0x20];
	//Okay, we abuse the fact that, for the first actual file header, the first two bytes 
	//always are 0000. This means that we can get the initial XOR value by simply taking 
	//the 1st byte there.
	//There are more 0000 fields in there: if (LFSR ^ carry) returns a 0 there, the 2nd value simply 
	//is 2x the 1st value. If it's not, we can figure out the xorch value from there.
	
	//Note: This value seems to consistently be 0x21. I wrote the code, so I'll still check. Worst
	//case, this catches someone using a gibberish file.
	uint8_t xorinit=firstfe[0];
	uint8_t xorchg=-1;
	int found_xorchg=0;
	const int zeroes_off[]={0, 4, 8, 12, 13};
	for (int i=0; i<sizeof(zeroes_off)/sizeof(int); i++) {
		int idx=zeroes_off[i];
		int dup_1st=(firstfe[idx]*2)&0xff;
		if (firstfe[idx+1]!=dup_1st) {
			int new_xorchg=firstfe[idx+1]^dup_1st;
			if (found_xorchg && new_xorchg!=xorchg) {
				printf("Huh? Found two different xorch values: 0x%02X and 0x%02X.\n", new_xorchg, xorchg);
				printf("Image may be bogus.\n");
			}
			xorchg=new_xorchg;
			found_xorchg=1;
		}
	}
	if (!found_xorchg) {
		printf("Didn't find xorchg... using default of 0x21.\n");
		xorchg=0x21;
	}

	printf("Found initial xor value of 0x%02X, xor with 0x%02X on carry^lfsr\n", xorinit, xorchg);
	//Find a viable lfsr stream to decode the entry. We do this recursive.
	uint8_t dec[64];
	uint8_t keystream[64]={0};
	find_valid_lfsr_output_for_byte(firstfe, dec, 0, xorinit, xorchg, keystream);


	printf("Checked all lfsr keystreams.\n");

}
