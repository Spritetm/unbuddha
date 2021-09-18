#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t res=0xCD82058E2C0C8880;

int check_lfsr(uint32_t state, uint32_t taps, int len) {
	uint64_t tst=res;
	for (int i=0; i<64; i++) {
		int newbit=__builtin_popcount(state&taps)&1;
		state>>=1;
		state|=(newbit<<len);
		if (newbit != (tst&1)) return 0;
		tst>>=1;
	}
	return 1;
}

int main(int argc, char **argv) {
	for (int i=0; i<0xffff; i++) {
		for (int j=0; j<0xffff; j++) {
			if (check_lfsr(i, j, 16)) {
				printf("state %x taps %x\n", i, j);
				exit(0);
			}
		}
		printf("state %d\n", i);
	}
}
