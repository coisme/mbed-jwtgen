#ifndef __JWTGEN_H__
#define __JWTGEN_H__

#include "mbed.h"

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
            const char* aud, time_t iat, time_t exp);
};

#endif
