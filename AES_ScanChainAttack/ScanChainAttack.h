#include <stdio.h>
#include <time.h>


#include <string>
#include <bitset> 
#include <vector>

#ifndef _SCAN_CHAIN
	#define _SCAN_CHAIN
	
	void phex(uint8_t* str, int len);

	void test1(struct AES_ctx ctx, uint8_t* plain_text, int length);
	void test2(struct AES_ctx ctx);	
	void XOR(uint8_t outArr[], uint8_t byteArr1[], uint8_t byteArr2[]);
	int countbits(uint8_t str[], int length);

	bool compare(uint8_t str01[], uint8_t str02[], int length);
	bool attack(uint8_t trial_key[], AES_ctx ctx);

	struct scan{
		uint8_t s_input[2];
		uint8_t b_state[2];
		uint8_t opt_key[4];
	};

	//Scans an emulated ciphering unit ctx
	std::vector<scan> scan_data(struct AES_ctx ctx);
	void buildKey(uint8_t key[], std::vector<scan> scan_options, uint16_t index, int index2);
#endif