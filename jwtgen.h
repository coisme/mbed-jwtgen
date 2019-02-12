#ifndef __JWTGEN_H__
#define __JWTGEN_H__

#include "mbed.h"
#include "mbedtls/pk.h"

class JwtGenerator {
public:
    enum Status {
        SUCCESS = 0,
        ERROR = -1,
        ERROR_MEMORY_ALLOCATION = -10,
        ERROR_BUFFER_SIZE_NOT_ENOUGH = -11,
        ERROR_PARSE_KEY = -12,
        ERROR_BAD_KEY_TYPE = -13
    };
    
    enum Algorithm {
        ALG_RS256,
        ALG_ES256
    };

    /** Generates JSON Web Tokens (JWT). 
     * Currently the generated token has only required fields to connect Google Cloud IoT Core.
     * For details, see https://cloud.google.com/iot/docs/how-tos/credentials/jwts
     * 
     * @param buf Pointer to the buffer to store the generated token.
     * @param buf_len Size of the buffer.
     * @param olen Pointer to store the length of JWT.
     * @param private_key_pem Pointer to your private key stored in PEM format.
     * @param aud Pointer to the Audience field string.
     * @param iat Timestamp for Issured At field.
     * @param exp Timestamp for Expilation field.
     * @return SUCCESS when JWT is generated successfully. 
     * 
     * @note
     * Crypt algorithm is determinted from information in the private key.
     * 
     */
    static Status getJwt(char* buf, const size_t buf_len, size_t *olen, const char* private_key_pem,
            const char* aud, const time_t & iat, const time_t & exp);

private:
    /* Gets key type from the given private key in PEM format.
     *
     * @param t_pk Pointer to the key type store.
     * @param private_key_pem Pointer to your private key in PEM format.
     * 
     * @return SUCCESS when succeed. ERROR_* in failure.
     */
    static Status getKeyType(mbedtls_pk_type_t* t_pk, const char* private_key_pem);
    
    /* Gets a header part of JWT.
     *
     * @param buf Pointer to the buffer to store the header string in Base64 format.
     * @param buf_len Length of the buffer.
     * @param olen Pointer to a variable which stores the length of Base64 encoded header string.
     * @param t_pk Key type.
     * 
     * @return SUCCESS when succeed. ERROR* in failure.
     */
    static Status getHeaderBase64(char* buf, size_t buf_len, size_t *olen, mbedtls_pk_type_t t_pk);

    /* Gets a claim part of JWT.
     *
     * @param buf Pointer to the buffer to store the claim string in Base64 format.
     * @param buf_len Length of the buffer.
     * @param olen Pointer to a variable which stores the length of Base64 encoded claim string.
     * @param aud Pointer to an Audience field value.
     * @param iat Issued At field value.
     * @param exp Expiration field value.
     * 
     * @return SUCCESS when succeed. ERROR* in failure.
     * 
     * @note Project ID in Google Cloud IoT Core should be put into the Audience field.
     */
    static Status getClaimBase64(char *buf, size_t buf_len, size_t *olen, const char* aud, const time_t & iat, const time_t & exp);

    /* Gets a signature part of JWT.
     *
     * @param buf Pointer to the buffer to store the sign string in Base64 format.
     * @param buf_len Length of the buffer.
     * @param olen Pointer to a variable which stores the length of Base64 encoded sign string.
     * @param blob Pointer to the string which to be hashed, i.e. "{Base64 encoded header}.{Base64 encoded claim}".
     * @param blob_len Length of the blob.
     * @param private_key_pem Pointer to your private key stored in PEM format.
     * 
     * @return SUCCESS when succeed. ERROR* in failure.
     */    
    static Status getSignatureBase64(char *buf, size_t buf_len, size_t *olen, const char* blob, size_t blob_len, const char* private_key_pem);
};

#endif
