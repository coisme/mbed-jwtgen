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
    // Parse the private key
    mbedtls_pk_type_t t_pk = MBEDTLS_PK_NONE;
    if((status = getKeyType(&t_pk, private_key_pem)) != SUCCESS) {
        tr_error("Parsing key failed.");
        return status;
    }

    // check key type
    if((t_pk != MBEDTLS_PK_RSA) && (t_pk != MBEDTLS_PK_ECDSA)) {
        tr_error("Failed. Wrong key type.");
        return ERROR_BAD_KEY_TYPE;
    }

    /*
     * Create header
     */
    size_t header_b64_len = 0;
    if((status = getHeaderBase64(buf, buf_len, &header_b64_len, t_pk)) != SUCCESS) {
        tr_error("Failed to convert header into Base64 format.");
        return status;
    }
    index = header_b64_len;
    buf[index++] = '.';
    tr_debug("base64(header): %.*s", header_b64_len, buf);

    /*
     * Create claim
     */
    // Store a claim into the given buffer temporary
    size_t claim_b64_len = 0;
    int max_claim_len = buf_len - index - LEN_EOS;
    if((status = getClaimBase64(buf+index, max_claim_len, &claim_b64_len, aud, iat, exp)) != SUCCESS) {
        tr_error("Failed to convert claim into Base64 format.");
        return status;
    }
    tr_debug("base64(claim): %.*s", claim_b64_len, buf+index);
    index += claim_b64_len;
    buf[index++] = '.';

    /*
     * Create Sign
     */
    size_t sign_b64_len;
    if((status = getSignatureBase64((buf + index), (buf_len - index), &sign_b64_len,
            buf, (header_b64_len + 1 + claim_b64_len), private_key_pem)) != SUCCESS) {
        tr_error("Failed to sign.");
        return status;
    }

    // total length of JWT
    *olen = header_b64_len + strlen(".") + claim_b64_len + strlen(".") + sign_b64_len;

    return status;
}


JwtGenerator::Status JwtGenerator::getKeyType(
        mbedtls_pk_type_t* t_pk, const char* private_key_pem)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int rc = 0;

    if((rc = mbedtls_pk_parse_key(&pk, (unsigned char *)private_key_pem,
            strlen(private_key_pem) + 1, NULL, 0)) != 0) {
        return ERROR_PARSE_KEY;
    }

    *t_pk = mbedtls_pk_get_type(&pk);

    return SUCCESS;
}


JwtGenerator::Status JwtGenerator::getHeaderBase64(
        char* buf, size_t buf_len, size_t *olen, mbedtls_pk_type_t t_pk) 
{
    const char* header_rs256 = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    const char* header_es256 = "{\"alg\": \"ES256\", \"typ\": \"JWT\"}";
    char* header = (char*)((t_pk == MBEDTLS_PK_RSA) ? header_rs256 : header_es256);

    tr_debug("header: %s", header);

    if(mbedtls_base64_encode((unsigned char*)buf, buf_len, olen, 
            (const unsigned char*)header, strlen(header)) != 0) {
        // rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
        return ERROR_BUFFER_SIZE_NOT_ENOUGH;
    }
    return SUCCESS;
}


JwtGenerator::Status JwtGenerator::getClaimBase64(
        char *buf, size_t buf_len, size_t *olen, const char* aud, time_t iat, time_t exp) 
{
    int len = snprintf(buf, buf_len, 
            "{\"aud\": \"%s\", \"iat\": %ld, \"exp\": %ld}", aud, iat, exp);

    if(len >= buf_len) {
        tr_error("Failed to construct claim. Needs more buffer size.");
        return ERROR_BUFFER_SIZE_NOT_ENOUGH;
    }

    // Allocate a temporary memory area
    char* claim = new char[len + LEN_EOS];
    // Copy the claim to the temporary area
    strncpy(claim, buf, len + LEN_EOS);
    tr_debug("claim: %s", claim);

    // Base64 encoding
    if(mbedtls_base64_encode((unsigned char*)(buf), buf_len, 
            olen, (const unsigned char*)claim, strlen(claim)) != 0) {
        // rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
        tr_error("Failed to encode claim into Base64. Buffer too small.");
        return ERROR_BUFFER_SIZE_NOT_ENOUGH;
    }
    // Delete the temporary memory area
    delete claim;

    return SUCCESS;
}


JwtGenerator::Status JwtGenerator::getSignatureBase64(
        char *buf, size_t buf_len, size_t *olen, const char* blob, size_t blob_len,
        const char* private_key_pem)
{
    int rc = 0;

    // Calculate hash
    unsigned char hash[32];
    if(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
            (const unsigned char*)blob, blob_len, hash) != 0){
        // MBEDTLS_ERR_MD_BAD_INPUT_DATA
        tr_err("Failed to calculate hash.");
        return ERROR;
    }

    // Parse key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if(mbedtls_pk_parse_key(&pk, (unsigned char *)private_key_pem,
        strlen(private_key_pem) + 1, NULL, 0) != 0) {
        return ERROR_PARSE_KEY;
    }

    // Set up CTR-DRBG
    const char *pers = "mbedtls_pk_sign";
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Set up entropy
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            (const unsigned char *)pers, strlen(pers));
    mbedtls_entropy_free(&entropy);
    
    if(rc != 0) {
        // MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
        tr_err("Failed in mbed_tls_ctr_drbg_seed().");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return ERROR;
    }

    // Sign
    size_t sig_len;
    rc = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, (unsigned char*)buf,
            &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);

    if(rc != 0) {
        tr_err("Failed in mbedtls_pk_sign.");
        return ERROR_PARSE_KEY;
    }

    // Copy to a temporary buffer
    char* sign = new char[sig_len];
    memcpy(sign, buf, sig_len);

    // Base64 encode
    mbedtls_base64_encode((unsigned char*)buf, buf_len, olen,
            (const unsigned char*)sign, sig_len);
    tr_debug("Base64(sign): %.*s", olen, buf);
    delete sign;

    return SUCCESS;
}
