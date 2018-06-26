#ifndef __JWTGEN_H__
#define __JWTGEN_H__

#include "mbed.h"

class JwtGenerator {
public:
    enum Status {
        SUCCESS,
        ERROR
    };
    
    enum Algorithm {
        ALG_RS256,
        ALG_ES256
    };

    Status getJwt(char* buf, const size_t buf_len, size_t *olen, const char* aud, time_t iat, time_t exp, Algorithm alg = ALG_RS256);
    void setPrivateKey(const char* private_key_pem);

private:
    char* _private_key_pem;
};

#endif
