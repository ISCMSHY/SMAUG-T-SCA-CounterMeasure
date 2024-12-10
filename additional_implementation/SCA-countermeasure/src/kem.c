#include "kem.h"

/*************************************************
 * Name:        crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Module-Lizard key encapsulation mechanism.
 *
 * Arguments:   - public_key *pk: pointer to output public key
 *                (a structure composed of (seed of A, matrix A, vector b))
 *              - secret_key *sk: pointer to output private key
 *                (a structure composed of (vector s, t, vector negstart))
 **************************************************/
void crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t static_seed[CRYPTO_BYTES] = {0xa8, 0x60, 0x14, 0x9e, 0x75, 0xd9, 0xe1, 0xee, 0x86, 0xfd, 0x36, 0xdc, 0xec, 0xf2, 0xaa, 0xab, 0x3d, 0x3f, 0x86, 0xcb, 0x39, 0xc7, 0xe8, 0x96, 0xb3, 0x86, 0xe6, 0x74, 0xfa, 0xf4, 0xd9, 0x52};
    uint8_t static_tbytes[T_BYTES] = {0xa3, 0xfe, 0x53, 0x12, 0xdc, 0x3d, 0xd6, 0x74, 0xb1, 0x2f, 0x2e, 0xc2, 0x70, 0xbe, 0x20, 0x9d, 0x39, 0xdf, 0xf0, 0x6d, 0xd9, 0xba, 0x75, 0x18, 0xda, 0x1a, 0x9d, 0x62, 0x19, 0xb7, 0xeb, 0xf0};

    indcpa_keypair(pk, sk, static_seed);
//    randombytes(sk + PKE_SECRETKEY_BYTES, T_BYTES);
    for(int i = 0; i < T_BYTES; i++)    // tbytes는 고정
            sk[PKE_SECRETKEY_BYTES + i] = static_tbytes[i];
    for (int i = 0; i < PUBLICKEY_BYTES; i++)
        sk[i + PKE_SECRETKEY_BYTES + T_BYTES] = pk[i];
}

void CM_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t static_seed[CRYPTO_BYTES] = {0xa8, 0x60, 0x14, 0x9e, 0x75, 0xd9, 0xe1, 0xee, 0x86, 0xfd, 0x36, 0xdc, 0xec, 0xf2, 0xaa, 0xab, 0x3d, 0x3f, 0x86, 0xcb, 0x39, 0xc7, 0xe8, 0x96, 0xb3, 0x86, 0xe6, 0x74, 0xfa, 0xf4, 0xd9, 0x52};
    uint8_t static_tbytes[T_BYTES] = {0xa3, 0xfe, 0x53, 0x12, 0xdc, 0x3d, 0xd6, 0x74, 0xb1, 0x2f, 0x2e, 0xc2, 0x70, 0xbe, 0x20, 0x9d, 0x39, 0xdf, 0xf0, 0x6d, 0xd9, 0xba, 0x75, 0x18, 0xda, 0x1a, 0x9d, 0x62, 0x19, 0xb7, 0xeb, 0xf0};

    CM_indcpa_keypair(pk, sk, static_seed); // seed로 인해 pk, sk는 동일
//    randombytes(sk + PKE_SECRETKEY_BYTES, T_BYTES);
    for(int i = 0; i < T_BYTES; i++)    // tbytes는 고정
        sk[PKE_SECRETKEY_BYTES + i] = static_tbytes[i];
    for (int i = 0; i < PUBLICKEY_BYTES; i++)
        sk[i + PKE_SECRETKEY_BYTES + T_BYTES] = pk[i];
}

/*************************************************
 * Name:        crypto_kem_enc
 *
 * Description: Generates ciphertext and shared
 *              secret for given public key.
 *
 * Arguments:   - ciphertext *ctxt: pointer to output ciphertext
 *                (a structure composed of (vector c21, c22))
 *              - unsigned char *ss: pointer to output shared secret
 *                (an already allocated array of CRYPTO_BYTES bytes)
 *              - public_key *pk: pointer to output public key
 *                (a structure composed of (seed of A, matrix A, vector b))
 *
 * Returns 0(success) or 1(failure).
 **************************************************/
int crypto_kem_enc(uint8_t *ctxt, uint8_t *ss, const uint8_t *pk) {
    // seed 값 고정
    uint8_t mu[DELTA_BYTES] = {0x61, 0xae, 0xe3, 0x2, 0xd0, 0x77, 0x3a, 0x3e, 0xcd, 0xc, 0xaf, 0xfb, 0x40, 0xeb, 0xd0, 0x24, 0xe4, 0xa0, 0xf7, 0x88, 0x49, 0xf0, 0xdb, 0x40, 0x42, 0x4c, 0x60, 0xf4, 0xbe, 0xf0, 0x2e, 0xe9}; // shared secret and seed
    uint8_t buf[DELTA_BYTES + CRYPTO_BYTES] = {0xfd, 0xa0, 0xb8, 0xcd, 0xb5, 0xfd, 0x33, 0x14, 0x43, 0x2, 0x8e, 0x9b, 0xc0, 0x18, 0x52, 0xd3, 0x5d, 0xaa, 0xb2, 0x8b, 0x3a, 0xcd, 0xe9, 0x68, 0xa7, 0xad, 0x26, 0xbf, 0xaf, 0xd6, 0x16, 0xca, 0xe8, 0x9b, 0xc0, 0x18, 0x65, 0x5c, 0xe4, 0xc7, 0xa5, 0xf1, 0x49, 0x5a, 0xb6, 0x2d, 0x89, 0x4, 0x1b, 0x1f, 0x79, 0x1b, 0xa3, 0xf, 0xbc, 0x9e, 0xf6, 0x84, 0x30, 0x38, 0x1f, 0x70, 0xd, 0x2d};

//    randombytes(mu, DELTA_BYTES);
//    hash_h(buf, pk, PUBLICKEY_BYTES);
//    hash_g(buf, DELTA_BYTES + CRYPTO_BYTES, mu, DELTA_BYTES, buf,
//           SHA3_256_HashSize);

    indcpa_enc(ctxt, pk, mu, buf);
    cmov(ss, buf + DELTA_BYTES, CRYPTO_BYTES, 1);

    return 0;
}

/*************************************************
 * Name:        crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              ciphertext and private key.
 *
 * Arguments:   - unsigned char *ss: pointer to output shared secret
 *                (an already allocated array of CRYPTO_BYTES bytes)
 *              - secret_key *sk: pointer to input private key
 *                (a structure composed of (vector s, t, vector negstart))
 *              - public_key *pk: pointer to input public key
 *                (a structure composed of (seed of A, matrix A, vector b))
 *              - ciphertext *ctxt: pointer to input ciphertext
 *                (a structure composed of (vector c21, c22))
 *
 * Returns 0(success) or 1(failure).
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
int crypto_kem_dec(uint8_t *ss, const uint8_t *ctxt, const uint8_t *sk) {
    uint8_t mu[DELTA_BYTES] = {0};
    uint8_t buf[DELTA_BYTES + CRYPTO_BYTES] = {0}; // shared secret and seed
    uint8_t buf_tmp[DELTA_BYTES + CRYPTO_BYTES] = {0};
    uint8_t hash_res[SHA3_256_HashSize] = {0};
    const uint8_t *pk = sk + PKE_SECRETKEY_BYTES + T_BYTES;

    indcpa_dec(mu, sk, ctxt);
    hash_h(hash_res, pk, PUBLICKEY_BYTES);
    hash_g(buf, DELTA_BYTES + CRYPTO_BYTES, mu, DELTA_BYTES, hash_res,
           SHA3_256_HashSize);

    uint8_t ctxt_temp[CIPHERTEXT_BYTES] = {0};
    indcpa_enc(ctxt_temp, pk, mu, buf);

    int fail = verify(ctxt, ctxt_temp, CIPHERTEXT_BYTES);

    hash_h(hash_res, ctxt, CIPHERTEXT_BYTES);
    hash_g(buf_tmp, DELTA_BYTES + CRYPTO_BYTES,
           sk + 2 * MODULE_RANK + SKPOLYVEC_BYTES, T_BYTES, hash_res,
           SHA3_256_HashSize);

    cmov(buf + DELTA_BYTES, buf_tmp + DELTA_BYTES, CRYPTO_BYTES, fail);
    cmov(ss, buf + DELTA_BYTES, CRYPTO_BYTES, 1);
    return 0;
}

int CM_crypto_kem_dec(uint8_t *ss, const uint8_t *ctxt, const uint8_t *sk) {
    uint8_t mu[DELTA_BYTES] = {0};
    uint8_t buf[DELTA_BYTES + CRYPTO_BYTES] = {0}; // shared secret and seed
    uint8_t buf_tmp[DELTA_BYTES + CRYPTO_BYTES] = {0};
    uint8_t hash_res[SHA3_256_HashSize] = {0};
    const uint8_t *pk = sk + PKE_SECRETKEY_BYTES + T_BYTES;

    CM_indcpa_dec(mu, sk, ctxt);
    hash_h(hash_res, pk, PUBLICKEY_BYTES);
    hash_g(buf, DELTA_BYTES + CRYPTO_BYTES, mu, DELTA_BYTES, hash_res,
           SHA3_256_HashSize);

    uint8_t ctxt_temp[CIPHERTEXT_BYTES] = {0};
    indcpa_enc(ctxt_temp, pk, mu, buf);

    int fail = verify(ctxt, ctxt_temp, CIPHERTEXT_BYTES);

    hash_h(hash_res, ctxt, CIPHERTEXT_BYTES);
    hash_g(buf_tmp, DELTA_BYTES + CRYPTO_BYTES,
           sk + 2 * MODULE_RANK + SKPOLYVEC_BYTES, T_BYTES, hash_res,
           SHA3_256_HashSize);

    cmov(buf + DELTA_BYTES, buf_tmp + DELTA_BYTES, CRYPTO_BYTES, fail);
    cmov(ss, buf + DELTA_BYTES, CRYPTO_BYTES, 1);
    return 0;
}
