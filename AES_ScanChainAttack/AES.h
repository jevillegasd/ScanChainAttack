//Header file for AES

#ifndef _AES_H_
    #define _AES_H_

    #include <stdint.h>

    // #define the macros below to 1/0 to enable/disable the mode of operation.
    //
    // CBC enables AES encryption in CBC-mode of operation.
    // CTR enables encryption in counter-mode.
    // ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

    #ifndef CBC
    #define CBC 1
    #endif
    #ifndef ECB
    #define ECB 1
    #endif
    #ifndef CTR
    #define CTR 1
    #endif

    #define AES128
    //#define AES192 1
    //#define AES256 1

    #define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

    #if defined(AES256) && (AES256 == 1)
        #define AES_KEYLEN 32
        #define AES_keyExpSize 240
    #elif defined(AES192) && (AES192 == 1)
        #define AES_KEYLEN 24
        #define AES_keyExpSize 208
    #else
        #define AES_KEYLEN 16   // Key length in bytes
        #define AES_keyExpSize 176
    #endif


    // state - array holding the intermediate results during decryption.
    typedef uint8_t state_t[4][4];

    struct AES_ctx
    {
        uint8_t RoundKey[AES_keyExpSize];
        #if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
            uint8_t Iv[AES_BLOCKLEN];
        #endif
    };

    void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
    #if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
        void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
        void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
    #endif

    #if defined(ECB) && (ECB == 1)
    // buffer size is exactly AES_BLOCKLEN bytes; 
    // you need only AES_init_ctx as IV is not used in ECB 
    // NB: ECB is considered insecure for most uses
        void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
        void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
    #endif // #if defined(ECB) && (ECB == !)


    #if defined(CBC) && (CBC == 1)
    // buffer size MUST be mutile of AES_BLOCKLEN;
    // Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
    // NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
    //        no IV should ever be reused with the same key 
        void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
        void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

    #endif // #if defined(CBC) && (CBC == 1)

    #if defined(CTR) && (CTR == 1)

    // Same function for encrypting as for decrypting. 
    // IV is incremented for every block, and used after encryption as XOR-compliment for output
    // Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
    // NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
    //        no IV should ever be reused with the same key 
        void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
    #endif // #if defined(CTR) && (CTR == 1)

//// Function declaration
    #define getSBoxValue(num) (sbox[(num)]);
    #define getSBoxInvert(num) (rsbox[(num)])

    // MixColumns function mixes the columns of the state matrix
    void MixColumns(state_t* state);
   
    // This function adds the round key to state.
    // The round key is added to the state by an XOR function.
    static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);
    
    static void InvAddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);

    // The SubBytes Function Substitutes the values in the
    // state matrix with values in an S-box.
    // static void SubBytes(state_t* state);

    // The ShiftRows() function shifts the rows in the state to the left.
    // Each row is shifted with different offset.
    // Offset = Row number. So the first row is not shifted.
    static void ShiftRows(state_t* state);


    // This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
    static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key);


    // Multiply is used to multiply numbers in the field GF(2^8)
    // Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
    //       The compiler seems to be able to vectorize the operation better this way.
    //       See https://github.com/kokke/tiny-AES-c/pull/34
    #if MULTIPLY_AS_A_FUNCTION
        {static __int8 Multiply(__int8 x, __int8 y); }
    #else {
        #define Multiply(x, y)                                \
              (  ((y & 1) * x) ^                              \
              ((y>>1 & 1) * xtime(x)) ^                       \
              ((y>>2 & 1) * xtime(xtime(x))) ^                \
              ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
              ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \
        }
    #endif

#endif //_AES_H_