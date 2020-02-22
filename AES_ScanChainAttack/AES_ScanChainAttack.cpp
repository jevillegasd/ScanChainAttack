// AES_ScanChainAttack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//Degubgging Macros

#define _PRINT_CIPHER


#include <iostream>
#include"ScanChainAttack.h"
#include<stdio.h>
#include "AES.cpp"
#include<string>
#include <bitset> 

using namespace std;
int main()
{
    std::cout << "AES Scan Chain Attack.\n";
    //test1();

    uint8_t key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    cout << "\nRound key: ";
    phex(key, sizeof(key) / sizeof(uint8_t) - 1);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    cout << "\nRound key: ";
    phex(ctx.RoundKey, sizeof(ctx.RoundKey) / sizeof(uint8_t) - 1);

    uint8_t plain_text1[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    uint8_t plain_text2[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    Cipher_1R((state_t*)plain_text1, ctx.RoundKey);
        std::cout << "\nState 1: ";
        phex(plain_text1, sizeof(plain_text1) / sizeof(uint8_t));
    Cipher_1R((state_t*)plain_text2, ctx.RoundKey);
        std::cout << "\nState 2: ";
        phex(plain_text2, sizeof(plain_text2) / sizeof(uint8_t));

    for (int i = 0; i < 15; i++)
        plain_text1[i] ^= plain_text2[i];
        std::cout << "\nXOR    : ";
    phex(plain_text1, sizeof(plain_text1) / sizeof(plain_text1[0]));

    int count = countbits(plain_text1, sizeof(plain_text1) / sizeof(plain_text1[0]));
    std::cout << "\nNoBits : " << count;

}

int countbits(uint8_t str[], int length) {
    int count = 0;
    for (int i = 0; i < length; i++) {
        bitset<8> bit = str[i];
        count += bit.count();
    }
    return count;
}



void phex(uint8_t str[], int len)
{   
    for (int i = 0; i < len; ++i)
        printf("%.2x", str[i]);
}

void test1() {
    // 128bit key
    uint8_t key[16] = { (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16, (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6, (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88, (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c };
    // 512bit text
    uint8_t plain_text[64] = { (uint8_t)0x6b, (uint8_t)0xc1, (uint8_t)0xbe, (uint8_t)0xe2, (uint8_t)0x2e, (uint8_t)0x40, (uint8_t)0x9f, (uint8_t)0x96, (uint8_t)0xe9, (uint8_t)0x3d, (uint8_t)0x7e, (uint8_t)0x11, (uint8_t)0x73, (uint8_t)0x93, (uint8_t)0x17, (uint8_t)0x2a,
                               (uint8_t)0xae, (uint8_t)0x2d, (uint8_t)0x8a, (uint8_t)0x57, (uint8_t)0x1e, (uint8_t)0x03, (uint8_t)0xac, (uint8_t)0x9c, (uint8_t)0x9e, (uint8_t)0xb7, (uint8_t)0x6f, (uint8_t)0xac, (uint8_t)0x45, (uint8_t)0xaf, (uint8_t)0x8e, (uint8_t)0x51,
                               (uint8_t)0x30, (uint8_t)0xc8, (uint8_t)0x1c, (uint8_t)0x46, (uint8_t)0xa3, (uint8_t)0x5c, (uint8_t)0xe4, (uint8_t)0x11, (uint8_t)0xe5, (uint8_t)0xfb, (uint8_t)0xc1, (uint8_t)0x19, (uint8_t)0x1a, (uint8_t)0x0a, (uint8_t)0x52, (uint8_t)0xef,
                               (uint8_t)0xf6, (uint8_t)0x9f, (uint8_t)0x24, (uint8_t)0x45, (uint8_t)0xdf, (uint8_t)0x4f, (uint8_t)0x9b, (uint8_t)0x17, (uint8_t)0xad, (uint8_t)0x2b, (uint8_t)0x41, (uint8_t)0x7b, (uint8_t)0xe6, (uint8_t)0x6c, (uint8_t)0x37, (uint8_t)0x10 };


    cout << "\nKey: ";
    phex(key, sizeof(key) / sizeof(uint8_t) - 1);

    cout << "\nMessage: ";
    phex(plain_text, sizeof(plain_text) / sizeof(uint8_t) - 1);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    for (uint8_t i = 0; i < 4; ++i)
        AES_ECB_encrypt(&ctx, plain_text + (i * 16));

    cout << "\nCiphertext: ";
    phex(plain_text, sizeof(plain_text) / sizeof(uint8_t) - 1);
}