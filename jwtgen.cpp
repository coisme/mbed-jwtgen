#include "mbed.h"
#include "jwtgen.h"

#define TRACE_GROUP "jwt"
#include "mbed-trace/mbed_trace.h"

#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

void JwtGenerator::setPrivateKey(const char* private_key_pem) {
    _private_key_pem = (char *)private_key_pem;
}

JwtGenerator::Status JwtGenerator::getJwt(char* buf, const size_t buf_len, size_t *olen, const char* aud, time_t iat, time_t exp, JwtGenerator::Algorithm alg) {
    /*
     * Create header
     */
    const size_t max_header_len = 128;
    char* header = new char[max_header_len];
    char* str_rs256 = "RS256";
    char* str_es256 = "ES256";
    char* str_alg = (alg == ALG_RS256 ? str_rs256 : str_es256);
    int header_len = snprintf(header, max_header_len, "{\"alg\": \"%s\", \"typ\": \"JWT\"}", str_alg);
    // Todo: error handling
    tr_debug(header);

    const size_t max_header_b64_len = max_header_len + max_header_len / 2;
    char* header_b64 = new char[max_header_b64_len];
    size_t header_b64_len = 0;
    mbedtls_base64_encode((unsigned char*)header_b64, max_header_b64_len, &header_b64_len, (const unsigned char*)header, strlen(header));
    // Todo: error handling
    tr_debug(header_b64);
    delete header;

    /*
     * Create claim
     */
    const size_t max_claim_len = 128;
    char* claim = new char[max_claim_len];
    int claim_len = snprintf(claim, max_claim_len, "{\"aud\": \"%s\", \"iat\": %ld, \"exp\": %ld}", aud, iat, exp);
    tr_debug(claim);
    // Todo: error handling

    const size_t max_claim_b64_len = max_claim_len + max_claim_len / 2;
    char* claim_b64 = new char[max_claim_b64_len];
    size_t claim_b64_len = 0;
    mbedtls_base64_encode((unsigned char*)claim_b64, max_claim_b64_len, &claim_b64_len, (const unsigned char*)claim, strlen(claim));
    // Todo: error handling
    tr_debug(header_b64);
    delete claim;

    memcpy(buf, header_b64, header_b64_len);
    buf[header_b64_len] = '.';
    memcpy(buf+header_b64_len+1, claim_b64, claim_b64_len);
    buf[header_b64_len+1+claim_b64_len] = '.';
    int index = header_b64_len + 1 + claim_b64_len + 1;

    /*
     * Sign
     */ 
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_sign";
    int ret = -1;

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pk );

    // Set up entropy
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        tr_err("err1");
        return ERROR;
    }

    // Parse the private key
    if((ret = mbedtls_pk_parse_key(&pk, (unsigned char *)_private_key_pem,
            strlen(_private_key_pem) + 1, NULL, 0)) != 0) {
        tr_err("err2");
        return ERROR;
    }

    // Calculate hash
    unsigned char hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char*)buf, header_b64_len + 1 + claim_b64_len, hash);
    tr_debug("Hash calculated.");

    // Sign
    char* sig = new char[1024];
    size_t siglen = 0;
    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, (unsigned char*)sig, &siglen,
                            mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
        {
            tr_err("err3");
            return ERROR;
        }
    tr_debug("Signing done.");

    // Base64 encode
    size_t sub_len = 0;
    mbedtls_base64_encode((unsigned char*)(buf+index), (buf_len - index), &sub_len, (const unsigned char*)sig, siglen);
    tr_debug("Base64 encoded.");

    delete sig;

    *olen = header_b64_len + strlen(".") + claim_b64_len + strlen(".") + sub_len;

    return SUCCESS;
}
