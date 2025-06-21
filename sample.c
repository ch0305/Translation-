#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "sample.h"

void get_utc_date(int64_t timestamp, char *utc, int len) {
    struct tm sttime;
    sttime = *gmtime(&timestamp);
    strftime(utc, len, "%Y-%m-%d", &sttime);
}

void sha256_hex(const char *str, char *result) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, str, strlen(str)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    EVP_MD_CTX_free(ctx);
  
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(result + 2 * i, "%02x", hash[i]);
    }
}

void hmac_sha256(const char* key, int key_len,
                 const char* input, int input_len,
                 unsigned char* output, size_t* output_len)  
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        *output_len = 0;
        return;
    }
    
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, 
                                        (const unsigned char*)key, key_len);
    if (!pkey) {
        EVP_MD_CTX_free(ctx);
        *output_len = 0;
        return;
    }
    
    size_t tmp_len = EVP_MAX_MD_SIZE;
    
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestSignUpdate(ctx, input, input_len) != 1 ||
        EVP_DigestSignFinal(ctx, output, &tmp_len) != 1) { 
        *output_len = 0;
    } else {
        *output_len = tmp_len;  
    }
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

void hex_encode(const char* input, int input_len, char* output) {
    for (int i = 0; i < input_len; i++) {
        sprintf(output + 2 * i, "%02x", (unsigned char)input[i]);
    }
    output[2 * input_len] = '\0';
}
void lowercase(const char *src, char *dst) {
    for (int i = 0; src[i]; i++) {
        dst[i] = tolower(src[i]);
    }
    dst[strlen(src)] = '\0';
}
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t totalSize = size * nmemb;
    struct WriteData *data = (struct WriteData *)userdata;
  
    if (data->response == NULL) {
        data->response = malloc(totalSize + 4096);
        if (!data->response) return 0;
        data->size = 0;
    } else {
        char *new_ptr = realloc(data->response, data->size + totalSize + 1);
        if (!new_ptr) return 0;
        data->response = new_ptr;
    }
    
    memcpy(data->response + data->size, ptr, totalSize);
    data->size += totalSize;
    data->response[data->size] = '\0';
    return totalSize;
}
