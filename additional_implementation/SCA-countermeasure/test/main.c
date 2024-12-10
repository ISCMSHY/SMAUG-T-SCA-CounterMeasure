#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "kem.h"
#include "pack.h"
#include "parameters.h"
#include "poly.h"
#include "randombytes.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

#define m_size 10

int indcpa_test();
int CM_indcpa_test();
int kem_test();
int CM_kem_test();

static inline uint64_t read_cycles(void) {
    uint64_t cycles;
    asm volatile("mrs %0, cntvct_el0" : "=r" (cycles));
    return cycles;
}

uint64_t start_cycles, end_cycles;

int main(void) {
    time_t mytime = time(NULL);
    char *time_str = ctime(&mytime);
    time_str[strlen(time_str) - 1] = '\0';
    printf("\n*** %s with mode %d starts at %s\n", "SMAUG KEM", SMAUG_MODE,
           time_str);

    struct timespec start, end;

//    clock_gettime(CLOCK_MONOTONIC, &start); // 여기서부터 수정
    start_cycles = read_cycles();
    int test_result = CM_kem_test();
//    int test_result = kem_test();
    end_cycles = read_cycles();
//    clock_gettime(CLOCK_MONOTONIC, &end);

    if (test_result) {
        printf("PKE test fails\n");
    }else {
        printf("PKE test success\n");
    }
//    double elapsed = (end.tv_sec - start.tv_sec) * 1000000000.0 + (end.tv_nsec - start.tv_nsec);
    uint64_t total_cycles = end_cycles - start_cycles;
    printf("Total cycles: %llu\n", total_cycles);
//    printf("PKE test elapsed time: %f ns\n", elapsed);


//    size_t count = 1;
//    const size_t iteration = 100000;
//
//    for (size_t i = 0; i < iteration; ++i) {
//        if (!(i % (iteration / 10))) {
//            printf("...%lu%%", count * 10);
//            fflush(stdout);
//            ++count;
//        }
//
//         if (indcpa_test()) {
//             printf("PKE test fails at %lu-th tries\n", i);
//             break;
//         }
//
//        if (kem_test()) {
//            printf("KEM test fails at %lu-th tries\n", i);
//            break;
//        }
//    }

    return 0;
}

int CM_indcpa_test(){
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[PKE_SECRETKEY_BYTES] = {0};
    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t mu[DELTA_BYTES] = {0}, mu2[DELTA_BYTES] = {0};
    uint8_t seed[DELTA_BYTES] = {0};
    uint8_t static_seed[CRYPTO_BYTES] = {0xa8, 0x60, 0x14, 0x9e, 0x75, 0xd9, 0xe1, 0xee, 0x86, 0xfd, 0x36, 0xdc, 0xec, 0xf2, 0xaa, 0xab, 0x3d, 0x3f, 0x86, 0xcb, 0x39, 0xc7, 0xe8, 0x96, 0xb3, 0x86, 0xe6, 0x74, 0xfa, 0xf4, 0xd9, 0x52};

    CM_indcpa_keypair(pk, sk, static_seed);
    // printf("indcpa_keypair done\n");

    randombytes(mu, DELTA_BYTES);
    randombytes(seed, DELTA_BYTES);

    indcpa_enc(ctxt, pk, mu, seed);
    // printf("indcpa_enc done\n");

//    indcpa_dec(mu2, sk, ctxt);
    CM_indcpa_dec(mu2, sk, ctxt);
//    printf("indcpa_dec done\n");

    if (memcmp(mu, mu2, DELTA_BYTES) != 0) {
        for (int i = 0; i < m_size; ++i)
            printf("0x%2hx ", mu[i]);
        printf("\n");

        for (int i = 0; i < m_size; ++i)
            printf("0x%2hx ", mu2[i]);
        printf("\n");
        return 1;
    }
    return 0;
}

int indcpa_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[PKE_SECRETKEY_BYTES] = {0};
    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t mu[DELTA_BYTES] = {0}, mu2[DELTA_BYTES] = {0};
    uint8_t seed[DELTA_BYTES] = {0};
    uint8_t static_seed[CRYPTO_BYTES] = {0xa8, 0x60, 0x14, 0x9e, 0x75, 0xd9, 0xe1, 0xee, 0x86, 0xfd, 0x36, 0xdc, 0xec, 0xf2, 0xaa, 0xab, 0x3d, 0x3f, 0x86, 0xcb, 0x39, 0xc7, 0xe8, 0x96, 0xb3, 0x86, 0xe6, 0x74, 0xfa, 0xf4, 0xd9, 0x52};

    indcpa_keypair(pk, sk, static_seed);
     printf("indcpa_keypair done\n");

    // 이것도 seed 통일하자.
    randombytes(mu, DELTA_BYTES);
    randombytes(seed, DELTA_BYTES);

    indcpa_enc(ctxt, pk, mu, seed);
     printf("indcpa_enc done\n");

    indcpa_dec(mu2, sk, ctxt);
    printf("indcpa_dec done\n");

    if (memcmp(mu, mu2, DELTA_BYTES) != 0) {
        for (int i = 0; i < m_size; ++i)
            printf("0x%2hx ", mu[i]);
        printf("\n");

        for (int i = 0; i < m_size; ++i)
            printf("0x%2hx ", mu2[i]);
        printf("\n");
        return 1;
    }
    return 0;
}

int kem_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};


    crypto_kem_keypair(pk, sk);
    // printf("Keygen_kem done\n");

    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t ss[CRYPTO_BYTES] = {0}, ss2[CRYPTO_BYTES] = {0};
    crypto_kem_enc(ctxt, ss, pk);
    // printf("Encap done\n");
//    for(int i = 0; i < CIPHERTEXT_BYTES; i++){
//        printf("0x%2hx ", ctxt[i]);
//    }

    int res = crypto_kem_dec(ss2, ctxt, sk);
    // printf("Decap done\n");

    if (memcmp(ss, ss2, CRYPTO_BYTES) != 0) {
        for (int i = 0; i < m_size; ++i) {
            printf("0x%2hx ", ss[i]);
        }
        printf("\n");

        for (int i = 0; i < m_size; ++i) {
            printf("0x%2hx ", ss2[i]);
        }
        printf("\n");
    }

    return res;
}

int CM_kem_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};


    CM_crypto_kem_keypair(pk, sk);
    // printf("Keygen_kem done\n");

    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t ss[CRYPTO_BYTES] = {0}, ss2[CRYPTO_BYTES] = {0};
    crypto_kem_enc(ctxt, ss, pk);
     printf("Encap done\n");

//    for(int i = 0; i < CIPHERTEXT_BYTES; i++){
//        printf("0x%2hx ", ctxt[i]);
//    }

    int res = CM_crypto_kem_dec(ss2, ctxt, sk);
     printf("Decap done\n");

    if (memcmp(ss, ss2, CRYPTO_BYTES) != 0) {
        for (int i = 0; i < m_size; ++i) {
            printf("0x%2hx ", ss[i]);
        }
        printf("\n");

        for (int i = 0; i < m_size; ++i) {
            printf("0x%2hx ", ss2[i]);
        }
        printf("\n");
    }

    return res;
}
