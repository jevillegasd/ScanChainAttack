//ScanChainAttack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//Degubgging Macros

//#define _PRINT_CIPHER
//#define _PRINT_BRUTE
//#define _PRINT_SCAN //Uncomment this one.
#define _PRINT_ATTACK
#define _PRINT_TEST

#define STRICT
#define WIN32_LEAN_AND_MEAN

#include<stdlib.h>
#include<stdio.h>
#include<sstream>  //Buffer
#include<conio.h>
#include<string.h>
#include<windows.h>


#include"ScanChainAttack.h"
#include"AES.h"
#include"simpleSerial.h"
#ifndef  state_t
    typedef uint8_t state_t[4][4];
#endif
using namespace std;
void scanAttack_top();


int main()
{
   /*//test if Comms are working*/
    uint8_t key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t plain_text[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int txt_Size = sizeof(plain_text) / sizeof(uint8_t);

    char port[128] = "\\\\.\\COM6";
    AES_ctx ctx(key,port);
    uint8_t ui8_str[16];
    
    std::cout << "\n1R Test Input :\t";	phex((uint8_t*)plain_text, 16);
    ctx.AES_Cipher1R(plain_text, txt_Size);
    std::cout << "\n1R Test output:\t";	phex((uint8_t*)plain_text, 16);
    ctx.close();
    


    scanAttack_top();
    return 0;
}


void scanAttack_top(){
    std::cout << "\nRunning AES Scan Chain Attack...\n";
    //AES_ctx ctx, ctx2; //AES machine key, ctx2 is configurerd with the found key (malicious)
    //uint8_t key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //uint8_t key[16] = {0x2F, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xAA, 0xa6, 0xab, 0xf7, 0x15, 0xFF, 0x09, 0xcf, 0x4f, 0x3c};
    //uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78};
    //uint8_t key[16] = {0x16, 0x69, 0x49, 0x52, 0x16, 0x69, 0x49, 0x52, 0x16, 0x69, 0x49, 0x52, 0x16, 0x69, 0x49, 0x52};
    uint8_t key[16] = {0x16, 0x66, 0x47, 0x38, 0x16, 0x66, 0x47, 0x38, 0x16, 0x66, 0x47, 0x38, 0x16, 0x66, 0x47, 0x38};
    uint8_t plain_text[64]  = "This is a secret nobody can know, please don't tell anyone o.k?";

    //uint8_t plain_text[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t cipher_text[64] = "";   
    uint8_t test_text[64] = "";     
    int text_length = sizeof(plain_text) / sizeof(uint8_t);
    
    char port[128] = "\\\\.\\COM6";
    AES_ctx ctx(key, port); //Remote (FPGA) AES oracle (only for the Cipher1R function)

    uint8_t guess_key[16];
    attack(guess_key, ctx);

#ifdef _PRINT_TEST
    std::cout << "\nTesting the obtained key using a new AES oracle...";
    std::cout << "\n\nShort key: \t"; phex(key, sizeof(key) / sizeof(uint8_t));
    std::cout << "\nRound key: \t"; phex(ctx.roundKey, sizeof(ctx.roundKey) / sizeof(uint8_t));
    std::cout << "\n\nGuess key: \t"; phex(guess_key, 16);
#endif

    //---- TEST OF THE OBTAINED KEY -----

    std::copy(begin(plain_text), std::end(plain_text), std::begin(cipher_text));
    for (uint8_t i = 0; i < text_length / 16; ++i)
        ctx.ECB_encrypt(cipher_text + (i * 16));    //Encrypts a cipher text.
    std::copy(begin(cipher_text), std::end(cipher_text), std::begin(test_text));
 
    AES_ctx ctx2(guess_key);    //Local AES oracle (malicious).
    
    for (uint8_t i = 0; i < text_length / 16; ++i)
        ctx2.ECB_encrypt(test_text + (i * 16));

#ifdef _PRINT_TEST 
    std::cout << "\n\nRunning test...";
    std::cout << "\nOriginal Text: (0x16)"; phex(plain_text , text_length);
    std::cout << "\nCipher Text  : (0x16)"; phex(cipher_text, text_length);
    std::cout << "\nHacked Text  : (0x16)"; phex(test_text  , text_length);
#endif
}


void buildKey(uint8_t key[], vector<scan> scan_options, uint16_t index, int index2) {
    //uint8_t key[16];

    for (int i = 0; i < 16; i++) {
        bool ind = (index>>i ) & 1;
        key[i] = scan_options[i].opt_key[ind];
    }
}

bool attack(uint8_t trial_key[], AES_ctx ctx) {
    //From here onwards, we cannot decrypt using the orale ctx, nor access its key.
    
    auto start = std::chrono::system_clock::now();
    vector<scan> scan_options;

    uint8_t plain_text[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    int text_length = sizeof(plain_text) / sizeof(uint8_t);
    uint8_t cipher_text[16];
    copy(std::begin(plain_text), std::end(plain_text), begin(cipher_text));

    scan_options = scan_data(ctx);       // First we get all possible keys scanning through the AES machine
    

    //AES_ECB_encrypt(ctx, cipher_text);   // We encrypt a known text and save the result.
    ctx.ECB_encrypt(cipher_text);

    int maxi = 1 << 16, i0; //Same as 2^16
    i0 = (rand() * 2) % maxi;
#ifdef _PRINT_ATTACK
    cout << "\nFound all possible key words. Attempting brute force through all combinations.";
    cout << "\nSeed: " << i0;
#endif 

    //Now we need to brute force through all the key options (2^16) and the 
    for (int i2 = 0; i2 < 2; i2++) { //Not really necessary
        for (int i = 0; i < maxi; i++) {
            int index = (i + i0) % maxi;    //We add the random i0 to add statistical relevance
            uint8_t temp_cipher_text[16];
            copy(std::begin(cipher_text), std::end(cipher_text), begin(temp_cipher_text));

            buildKey(trial_key, scan_options, (uint16_t)index, i2);
#ifdef _PRINT_BRUTE
            phex(trial_key,16);
#endif

            AES_ctx ctx2(trial_key); //Local AES Oracle
            ctx2.ECB_decrypt(temp_cipher_text);
            //AES_ECB_decrypt(ctx2, temp_cipher_text);

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
                          << "Elapsed time: " << elapsed_seconds.count() << "s. \n";
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

std::vector<struct scan> scan_data(AES_ctx ctx) {
    uint8_t t0=0, tot=0, count=0;
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
                result.s_input[0] = ((count_t+ t0) % 127) * 2; //Use the random generated t0 to add statistic relevance to our finding process
                result.s_input[1] = result.s_input[0]+1;

                ui8_str01[i * 4 + j] = result.s_input[0];
                ui8_str02[i * 4 + j] = result.s_input[1];

#ifdef _PRINT_SCAN
                std::cout << "\nIteration: " << count_t << "\t i :" << i << "\t j :" << j;
                std::cout << "\nINPUT_01 :\t"; phex((uint8_t*)ui8_str01, 16);
                std::cout << "\nINPUT_02 :\t"; phex((uint8_t*)ui8_str02, 16);
#endif

                ctx.AES_Cipher1R((uint8_t*) ui8_str01, txtLength);
                ctx.AES_Cipher1R((uint8_t*) ui8_str02, txtLength);

                //Cipher_1R((state_t*)ui8_str01, ctx.roundKey);
                //Cipher_1R((state_t*)ui8_str02, ctx.roundKey);
                
                XOR(ui8_strOR, ui8_str01, ui8_str02);
                count = countbits(ui8_strOR, 16);

#ifdef _PRINT_SCAN
                std::cout << "\nOUTPUT_01:\t"; phex((uint8_t*)ui8_str01, 16);
                std::cout << "\nOUTPUT_02:\t"; phex((uint8_t*)ui8_str02, 16);
                std::cout << "\nXOR      :\t"; phex((uint8_t*)ui8_strOR, 16);
                std::cout << "\n";
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

#ifdef _PRINT_ATTACK
            std::cout << "\nFound value for a" << i << j << " Input: ";
            phex((uint8_t*)result.s_input, 2);
            cout << ", Possibles b" << i << j << ": ";
            phex(result.b_state, 2);
            cout << " Number of trials = " << count_t;
#endif
        }
    }
#ifdef _PRINT_ATTACK
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
    cout << "\t";
    if (len ==1)
        printf("%.2x", (int) str);
    else
        for (int i = 0; i < len; ++i) {
            printf("%.2x", str[i]);
            if (i % 16 == 15 && i != len-1)
                cout << "\n\t\t\t";
        }

}

void test1(AES_ctx ctx, uint8_t* plain_text, int length) {
    //Tests encryption of a given plaintext.
    
    std::cout << "\nMessage: ";
    phex(plain_text, length);

    for (uint8_t i = 0; i < length/4; ++i)
        ctx.ECB_encrypt(plain_text + (i * 16));
        //AES_ECB_encrypt(ctx, plain_text + (i * 16));

    std::cout << "\nCiphertext: ";
    phex(plain_text, length);
}

void test2(AES_ctx ctx) {
    uint8_t ui8_str00[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    uint8_t ui8_str01[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    uint8_t ui8_OR[16];
    int txtLength = sizeof(ui8_str00) / sizeof(ui8_str00[0]);
    scan result;

    result.s_input[0] = 0xF2;  result.s_input[1] = result.s_input[0] + 1;

    ui8_str00[5] = result.s_input[0];
    ui8_str01[5] = result.s_input[1];

    Cipher_1R((state_t*)ui8_str00, ctx.roundKey);
    std::cout << "\nState 1: ";
    phex(ui8_str00, txtLength);


    Cipher_1R((state_t*)ui8_str01, ctx.roundKey);
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


void systemError(char* name) {
    // Retrieve, format, and print out a message from the last error.  The 
    // `name' that's passed should be in the form of a present tense noun 
    // (phrase) such as "opening file".
    //
    char* ptr = NULL;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        0,
        GetLastError(),
        0,
        (LPWSTR)&ptr,
        1024,
        NULL);

    fprintf(stderr, "\nError %s: %s\n", name, ptr);
    LocalFree(ptr);
}