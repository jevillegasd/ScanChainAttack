//ScanChainAttack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//Degubgging Macros

//#define _PRINT_CIPHER
//#define _PRINT_SCAN
#define _PRINT_ATTACK

#include <iostream>
#include <chrono>
#include <time.h> 

#include"ScanChainAttack.h"
#include"AES.cpp"

using namespace std;

int main()
{
    struct AES_ctx ctx;
    uint8_t key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //uint8_t key[16] = {0x2F, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xAA, 0xa6, 0xab, 0xf7, 0x15, 0xFF, 0x09, 0xcf, 0x4f, 0x3c };
    /*uint8_t plain_text[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,// };
                               (uint8_t)0xae, (uint8_t)0x2d, (uint8_t)0x8a, (uint8_t)0x57, (uint8_t)0x1e, (uint8_t)0x03, (uint8_t)0xac, (uint8_t)0x9c, (uint8_t)0x9e, (uint8_t)0xb7, (uint8_t)0x6f, (uint8_t)0xac, (uint8_t)0x45, (uint8_t)0xaf, (uint8_t)0x8e, (uint8_t)0x51,
                               (uint8_t)0x30, (uint8_t)0xc8, (uint8_t)0x1c, (uint8_t)0x46, (uint8_t)0xa3, (uint8_t)0x5c, (uint8_t)0xe4, (uint8_t)0x11, (uint8_t)0xe5, (uint8_t)0xfb, (uint8_t)0xc1, (uint8_t)0x19, (uint8_t)0x1a, (uint8_t)0x0a, (uint8_t)0x52, (uint8_t)0xef,
                               (uint8_t)0xf6, (uint8_t)0x9f, (uint8_t)0x24, (uint8_t)0x45, (uint8_t)0xdf, (uint8_t)0x4f, (uint8_t)0x9b, (uint8_t)0x17, (uint8_t)0xad, (uint8_t)0x2b, (uint8_t)0x41, (uint8_t)0x7b, (uint8_t)0xe6, (uint8_t)0x6c, (uint8_t)0x37, (uint8_t)0x10 };
    */
    uint8_t plain_text[64]  = "This is a secret nobody can know, please don't tell anyone o.k?";
    uint8_t cipher_text[64] = "";
    uint8_t test_text[64]   = "";

    int text_length = sizeof(plain_text) / sizeof(uint8_t);

    std::cout << "AES Scan Chain Attack.\n";
    std::cout << "\nShort key: "; phex(key, sizeof(key) / sizeof(uint8_t));
    AES_init_ctx(&ctx, key);
    std::cout << "\nRound key: "; phex(ctx.RoundKey, sizeof(ctx.RoundKey) / sizeof(uint8_t));
    
    //test2(ctx);               //Runs two example input text through 1 AES cycle of the AES machine ctx

    uint8_t guess_key[16];
    attack(guess_key, ctx);
    std::cout << "\nGuess Key :"; phex(guess_key, 16);
    
    
    //----------- Lets test what we got:
    std::cout << "\n\nRunning test...";
    std::cout << "\nOriginal Text: (STR ) " << plain_text;
    std::copy(begin(plain_text), std::end(plain_text), std::begin(cipher_text));
    for (uint8_t i = 0; i < text_length/16; ++i)
        AES_ECB_encrypt(&ctx, cipher_text + (i * 16));    //Encrypts a cipher text. plain_text now is encrypted and "safe"
    
    std::cout << "\nCipher Text  : (0x16)";  phex(cipher_text, text_length);
    //printf((char*) cipher_text);

    std::copy(begin(cipher_text), std::end(cipher_text), std::begin(test_text));

    struct AES_ctx ctx2;                                //Malicous AES machine with the found key
    AES_init_ctx(&ctx2, guess_key);
    for (uint8_t i = 0; i < text_length/16; ++i)
        AES_ECB_decrypt(&ctx, test_text + (i * 16));
    
    
    std::cout << "\nHacked Text  : (STR )  " << test_text;
    //cout << "\nCipher Text  : " << cipher_text; //Somehow this is printing also values from other variables

    

    return 0;
}

void buildKey(uint8_t key[], vector<scan> scan_options, uint16_t index, int index2) {
    //uint8_t key[16];

    for (int i = 0; i < 16; i++) {
        bool ind = (index>>i ) & 1;
        key[i] = scan_options[i].opt_key[ind];
    }
}

bool attack(uint8_t trial_key[], AES_ctx ctx) {
    auto start = std::chrono::system_clock::now();
   
    vector<scan> scan_options;
    std::cout << "\nStarting attack.";

    uint8_t plain_text[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    int text_length = sizeof(plain_text) / sizeof(uint8_t);
    uint8_t cipher_text[16];
    copy(std::begin(plain_text), std::end(plain_text), begin(cipher_text));

    scan_options = scan_data(ctx);       // First we get all possible keys scanning through the AES machine
    AES_ECB_encrypt(&ctx, cipher_text);  // We encrypt a known text and save the result.
    int maxi = 1 << 16, i0; //Same as 2^16
    i0 = (rand() * 2) % maxi;

    std::cout << "\nFound all possible key words. Attempting brute force through all combinations.";
    std::cout << "\nSeed: " << i0;
    //Now we need to brute force through all the key options (2^16) and the 

    for (int i2 = 0; i2 < 2; i2++) { //Not really necessary
        for (int i = 0; i < maxi; i++) {
            int index = (i + i0) % maxi;    //We add the random i0 to add statistical relevance
            uint8_t temp_cipher_text[16];
            copy(std::begin(cipher_text), std::end(cipher_text), begin(temp_cipher_text));

            //uint8_t trial_key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            buildKey(trial_key, scan_options, (uint16_t)index, i2);
            //cout << "\nTrying key "; phex(trial_key, 16);

            struct AES_ctx ctx2;
            AES_init_ctx(&ctx2, trial_key);
            AES_ECB_decrypt(&ctx2, temp_cipher_text);

            bool stat = compare(plain_text, temp_cipher_text, text_length);
            
            if (stat) {

#ifdef _PRINT_ATTACK
                std::cout << "\nMatch found on trial " << i2 * 65536 + i;
                std::cout << "\nFound using plain Text :"; phex(plain_text, 16);
                std::cout << "\nFinal attempeted guess :"; phex(temp_cipher_text, 16);
                std::cout << "\nRecovered key          :"; phex(trial_key, 16);

                auto end = std::chrono::system_clock::now();
                std::chrono::duration<double> elapsed_seconds = end - start;
                time_t end_time = std::chrono::system_clock::to_time_t(end);

                char str[26];
                ctime_s(str, sizeof str, &end_time);
                std::cout << "\nFinished computation at " << str
                          << "\nElapsed time: " << elapsed_seconds.count() << "s.";
#endif
                return 1;
            }
        }
    }
    std::cout << "\nUnable to find the key.";
    return 0;
}

bool compare(uint8_t str01[], uint8_t str02[], int length) {
    bool output = true;
    for (int i = 0; i < length; i++) {
        uint8_t s = str01[i] ^ str02[i];
        if (s != 0x00) {
            output = false;
            break;
        }
    }
    return output;
}

std::vector<struct scan> scan_data(struct AES_ctx ctx) {
    uint8_t t0, tot=0, count=0;
    uint8_t ui8_str00[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    uint8_t ui8_str01[16], ui8_str02[16], ui8_strOR[16];
    int txtLength = sizeof(ui8_str00) / sizeof(ui8_str00[0]);
    std::vector<scan> scan_options;

    srand(time(NULL));
    std::cout << "\nRunning scan of AES system...";
    for (int i = 0; i < 4; i++) { //Row cylce
        for (int j = 0; j < 4; j++) { //Column cycle
            t0 = rand() % 127; //This is a random seed to to test the bytes
            int count_t;
            scan result;
            for (count_t = 0; count_t < 127; count_t++) {
                std::copy(begin(ui8_str00), std::end(ui8_str00), std::begin(ui8_str01));
                std::copy(begin(ui8_str00), std::end(ui8_str00), std::begin(ui8_str02));
                result.s_input[0] = ((count_t+ t0) % 127) * 2; //Use use the random generated t0 add statistic relevance to our finding process
                result.s_input[1] = result.s_input[0]+1;

                ui8_str01[i * 4 + j] = result.s_input[0];
                ui8_str02[i * 4 + j] = result.s_input[1];


                Cipher_1R((state_t*)ui8_str01, ctx.RoundKey);
                Cipher_1R((state_t*)ui8_str02, ctx.RoundKey);
                
                XOR(ui8_strOR, ui8_str01, ui8_str02);
                count = countbits(ui8_strOR, 16);

#ifdef _PRINT_SCAN
                std::cout << "\nREG_01   :"; phex((uint8_t*)ui8_str01, 16);
                std::cout << "\nREG_02   :"; phex((uint8_t*)ui8_str02, 16);
                std::cout << "\nXOR      :"; phex((uint8_t*)ui8_strOR, 16);
#endif

                switch (count) {
                case(9):
                    result.b_state[0] = 226; result.b_state[1] = 227;
                    break;
                case(12):
                    result.b_state[0] = 242; result.b_state[1] = 243;
                    break;
                case(23):
                    result.b_state[0] = 122; result.b_state[1] = 123;
                    break;
                case(24):
                    result.b_state[0] = 130; result.b_state[1] = 131;
                    break;
                default:
                    continue;
                }
                tot += count_t;
                break;
            }
            result.opt_key[0] = result.b_state[0] ^ result.s_input[0];
            result.opt_key[1] = result.b_state[0] ^ result.s_input[1];
            result.opt_key[2] = result.b_state[1] ^ result.s_input[0];
            result.opt_key[3] = result.b_state[1] ^ result.s_input[1];

            scan_options.push_back(result);

#ifdef _PRINT_SCAN
            std::cout << "\nFound value for a" << i << j << " Input: ";
            phex((uint8_t*)result.s_input, 2);
            cout << ", Possibles b" << i << j << ": ";
            phex(result.b_state, 2);
            cout << " Number of trials = " << count_t;
#endif
        }
    }
#ifdef _PRINT_SCAN
    std::cout << "\nAverage trials: " << tot / 16;
#endif
    return scan_options;
}

void XOR(uint8_t outArr[],uint8_t byteArr1[], uint8_t byteArr2[]) {
    //uint8_t outArr[16];
    for (int i = 0; i < 16; i++)
        outArr[i] = byteArr1[i] ^ byteArr2[i];
}

int countbits(uint8_t str[], int length) {
    int count = 0;
    //cout << "\nCurrent Word to: "; phex(str, length);
    for (int i = 0; i < length; i++) {
        bitset<8> bit = str[i];
        count += bit.count();
    }
    return count;
}

void phex(uint8_t str[], int len)
{   
    if (len ==1)
        printf("%.2x", (int) str);
    else
        for (int i = 0; i < len; ++i) {
            if (i%16 == 0)
                cout << "\n\t\t\t";
            printf("%.2x", str[i]);
        }

}

void test1(struct AES_ctx ctx, uint8_t* plain_text, int length) {
    //Tests encryption of a given plaintext.
    
    std::cout << "\nMessage: ";
    phex(plain_text, length);

    for (uint8_t i = 0; i < length/4; ++i)
        AES_ECB_encrypt(&ctx, plain_text + (i * 16));

    std::cout << "\nCiphertext: ";
    phex(plain_text, length);
}

void test2(struct AES_ctx ctx) {
    uint8_t ui8_str00[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    uint8_t ui8_str01[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    uint8_t ui8_OR[16];
    int txtLength = sizeof(ui8_str00) / sizeof(ui8_str00[0]);
    scan result;

    result.s_input[0] = 0xF2;  result.s_input[1] = result.s_input[0] + 1;

    ui8_str00[5] = result.s_input[0];
    ui8_str01[5] = result.s_input[1];

    Cipher_1R((state_t*)ui8_str00, ctx.RoundKey);
    std::cout << "\nState 1: ";
    phex(ui8_str00, txtLength);


    Cipher_1R((state_t*)ui8_str01, ctx.RoundKey);
    std::cout << "\nState 2: ";
    phex(ui8_str01, txtLength);

    XOR(ui8_OR, ui8_str01, ui8_str00);
    std::cout << "\nXOR    : ";
    phex(ui8_OR, txtLength);

    int count = countbits(ui8_OR, txtLength);
    

    switch (count) {
    case(9):
        result.b_state[0] = 226; result.b_state[1] = 227;
        break;
    case(12):
        result.b_state[0] = 242; result.b_state[1] = 243;
        break;
    case(23):
        result.b_state[0] = 122; result.b_state[1] = 123;
        break;
    case(24):
        result.b_state[0] = 130; result.b_state[1] = 131;
        break;
    default:
        break;
    }

    result.opt_key[0] = result.b_state[0] ^ result.s_input[0];
    result.opt_key[1] = result.b_state[0] ^ result.s_input[1];
    result.opt_key[2] = result.b_state[1] ^ result.s_input[0];
    result.opt_key[3] = result.b_state[1] ^ result.s_input[1];
    

}