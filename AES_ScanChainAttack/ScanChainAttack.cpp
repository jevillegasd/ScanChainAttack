//ScanChainAttack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//Degubgging Macros

//#define _PRINT_CIPHER


#include <iostream>
#include"ScanChainAttack.h"
#include<stdio.h>
#include "AES.cpp"
#include<string>
#include <bitset> 
#include <time.h>
#include <vector>


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

    uint8_t ui8_str00[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ui8_str01[16], ui8_str02[16], option[2], t_vector[16];
    int txtLength = sizeof(ui8_str00) / sizeof(ui8_str00[0]), tot = 0;

    std::cout << "\nString 0:";  phex(ui8_str00, txtLength);
    
    uint8_t input, t0, count;
    srand(time(NULL));
    vector<uint8_t[2]> key_options;


    for (int i = 0; i < 4; i++) { //Row cylce
        for (int j = 0; j < 4; j++) { //Column cycle
            t0 = rand()%127; //This is a random seed to to test the bytes
            int count_t;
            for (count_t = 0; count_t < 127; count_t++) {
                copy(std::begin(ui8_str00), std::end(ui8_str00), std::begin(ui8_str01));
                copy(std::begin(ui8_str00), std::end(ui8_str00), std::begin(ui8_str02));
                input = ((count_t + t0) % 127) * 2;
                ui8_str01[i * 4 + j] = input;
                ui8_str02[i * 4 + j] = input + 1;

                //std::cout << "\nString 1:";  phex(ui8_str01, txtLength);
                //std::cout << "\nString 2:";  phex(ui8_str02, txtLength);

                Cipher_1R((state_t*)ui8_str01, ctx.RoundKey);
                Cipher_1R((state_t*)ui8_str02, ctx.RoundKey);

                XOR(ui8_str01, ui8_str02);
                count = countbits(ui8_str01, txtLength);

                switch (count) {
                    case(9):
                        option[0] = 226; option[1] = 227;
                        //key_options.push_back(option);
                        t_vector[i * 4 + j] = input;
                        break;
                    case(12):
                        option[0] = 242; option[1] = 243;
                        //key_options.push_back(option);
                        t_vector[i * 4 + j] = input;
                        break;
                    case(23):
                        option[0] = 122; option[1] = 123;
                        //key_options.push_back(option);
                        t_vector[i * 4 + j] = input;
                        break;
                    case(24):
                        option[0] = 130; option[1] = 131;
                        //key_options.push_back(option);
                        t_vector[i * 4 + j] = input;
                        break;
                    default:
                        continue;
                }
                tot += count_t;
                break;
            }


                std::cout << "\nFound value for a" << i << j <<" Input: "; 
                phex((uint8_t*) input, 1);
                cout << ", Possibles b" << i << j << ": ";
                phex(option, 2);
                cout << " Number of trials = " << count_t;
        }
    }
    std::cout << "\nAverage trials: " << tot/16;

    Cipher_1R((state_t*)ui8_str00, ctx.RoundKey);
        std::cout << "\nState 1: ";
        phex(ui8_str00, txtLength);
    
        
    Cipher_1R((state_t*)ui8_str01, ctx.RoundKey);
        std::cout << "\nState 2: ";
        phex(ui8_str01, txtLength);

        XOR(ui8_str01, ui8_str00);
        std::cout << "\nXOR    : ";
    phex(ui8_str01, txtLength);

    std::cout << "\nNoBits : " << count;

}

void XOR(uint8_t byteArr1[], uint8_t byteArr2[]) {
    for (int i = 0; i < 15; i++)
        byteArr1[i] ^= byteArr2[i];
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
    if (len ==1)
        printf("%.2x", str);
    else
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