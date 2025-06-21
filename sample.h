#ifndef SAMPLE_H
#define SAMPLE_H

#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <sys/types.h> 

void get_utc_date(int64_t timestamp, char *utc, int len);
void sha256_hex(const char *str, char *result);
void hmac_sha256(const char* key, int key_len,
                 const char* input, int input_len,
                 unsigned char* output, size_t* output_len); 
void hex_encode(const char* input, int input_len, char* output);
void lowercase(const char *src, char *dst);
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);

struct WriteData {
    char *response;
    size_t size;
};

#endif
