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

#define LEN_EOS    1         // Length of end of string, i.e. length of '\0'

JwtGenerator::Status JwtGenerator::getJwt(char* buf, const size_t buf_len, 
    size_t *olen, const char* private_key_pem, const char* aud, time_t iat,
    time_t exp)
{
    Status status = SUCCESS;
    int rc = 0;      // return code
    int index = 0;   // index of buf[]

    /*
     * Parse private key and get an algorithm type
     */
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    // Parse the private key
    if((rc = mbedtls_pk_parse_key(&pk, (unsigned char *)private_key_pem,
            strlen(private_key_pem) + 1, NULL, 0)) != 0) 
    {
        tr_err("Failed in mbedtls_pk_parse_key().");
        return ERROR_PARSE_KEY;
    }
    Algorithm alg = ALG_RS256;
    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(&pk);
    if(pk_type == MBEDTLS_PK_RSA) {
        alg = ALG_RS256;
    } else if(pk_type == MBEDTLS_PK_ECDSA) {
        alg = ALG_ES256;
    } else {
        tr_error("Bad key type.");
        mbedtls_pk_free(&pk);
        return ERROR_BAD_KEY_TYPE;
    }

    /*
     * Create header
     */
    const char* header_rs256 = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    const char* header_es256 = "{\"alg\": \"ES256\", \"typ\": \"JWT\"}";
    char* header = (char*)((alg == ALG_RS256) ? header_rs256 : header_es256);
    tr_debug("header: %s", header);

    size_t header_b64_len = 0;
    rc = mbedtls_base64_encode((unsigned char*)buf, buf_len, &header_b64_len, 
            (const unsigned char*)header, strlen(header));
    if(rc != 0) {
        // rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
        tr_error("Failed to encode header into Base64. Buffer too small.");
        return ERROR_BUFFER_SIZE_NOT_ENOUGH;
    }
    index = header_b64_len;
    buf[index++] = '.';
    tr_debug("base64(header): %.*s", header_b64_len, buf);

    /*
     * Create claim
     */
    // Store a claim into the given buffer temporary
    int max_claim_len = buf_len - index - LEN_EOS;
    rc = snprintf(buf+index, max_claim_len, "{\"aud\": \"%s\", \"iat\": %ld, \"exp\": %ld}", aud, iat, exp);
    if(rc >= max_claim_len) {
        tr_error("Failed to construct claim. Needs more buffer size.");
        return ERROR_BUFFER_SIZE_NOT_ENOUGH;
    }    
    // Allocate a temporary memory area
    char* claim = new char[rc + LEN_EOS];
    // Copy the claim to the temporary area
    strncpy(claim, buf+index, rc + LEN_EOS);
    tr_debug("claim: %s", claim);
    // Base64 encoding
    size_t claim_b64_len = 0;
    rc = mbedtls_base64_encode((unsigned char*)(buf+index), (buf_len - index), 
            &claim_b64_len, (const unsigned char*)claim, strlen(claim));
    if(rc != 0) {
        // rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
        tr_error("Failed to encode claim into Base64. Buffer too small.");
        status = ERROR_BUFFER_SIZE_NOT_ENOUGH;
    } else {
        tr_debug("base64(claim): %.*s", claim_b64_len, buf+index);
        index += claim_b64_len;
        buf[index++] = '.';
    }
    // Delete the temporary memory area
    delete claim;

    /*
     * Sign
     */ 
    const char *pers = "mbedtls_pk_sign";
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Set up entropy
    if(rc == 0) {
        mbedtls_entropy_context entropy;
        mbedtls_entropy_init(&entropy);
        rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                (const unsigned char *)pers, strlen(pers));
        if(rc != 0) {
            // MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
            tr_err("Failed in mbed_tls_ctr_drbg_seed().");
            status = ERROR;
        }
        mbedtls_entropy_free(&entropy);
    }

    // Calculate hash
    unsigned char hash[32];
    if(rc == 0) {
        rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
                (const unsigned char*)buf, header_b64_len + 1 + claim_b64_len, hash);
        if(rc != 0) {
            // MBEDTLS_ERR_MD_BAD_INPUT_DATA
            status = ERROR;
        } else {
            tr_debug("Hash calculated.");
        }
    }

    // Sign
    size_t len_sig;
    if(rc == 0) {
        rc = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, (unsigned char*)(buf+index),
                &len_sig, mbedtls_ctr_drbg_random, &ctr_drbg);
        if(rc != 0) {
            tr_err("Failed in mbedtls_pk_sign.");
            status = ERROR_PARSE_KEY;
        }
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);

    // Copy to a temporary buffer
    if(rc == 0) {
        char* sign = new char[len_sig];
        memcpy(sign, buf+index, len_sig);
        tr_debug("Signing done.");

        // Base64 encode
        size_t sign_b64_len;
        mbedtls_base64_encode((unsigned char*)(buf+index), (buf_len - index), &sign_b64_len,
                (const unsigned char*)sign, len_sig);
        tr_debug("Base64 encoded.");
        delete sign;
        *olen = header_b64_len + strlen(".") + claim_b64_len + strlen(".") + sign_b64_len;
    }

    return status;
}
