#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//uint64_t res1=0xCD82058E2C0C8880;
//uint64_t res2=0;
uint64_t res1=0x9B040B1C58191101;
uint64_t res2=0x007D0581572D4F85;


int check_lfsr(uint32_t state, uint32_t taps, int len) {
	uint64_t tst=res1;
	for (int i=0; i<120; i++) {
		int newbit=(__builtin_popcount(state&taps)+1)&1;
		state>>=1;
		state|=(newbit<<(len-1));
		if (newbit != (tst&1)) return 0;
		tst>>=1ULL;
		if (i==63) tst=res2;
	}
	return 1;
}

int main(int argc, char **argv) {
	res1>>=1ULL;
	if (res2&1) res1|=(1ULL<<63ULL);
	res2>>=1ULL;
	printf("%llX %llX\n", res2, res1);

	int len=16;
	for (int i=0; i<(1<<len)-1; i++) {
		for (int j=0; j<(1<<len)-1; j++) {
			if (check_lfsr(i, j, len)) {
				printf("state 0x%x taps 0x%x\n", i, j);
//				exit(0);
			}
		}
//		printf("state %d\n", i);
	}
}
