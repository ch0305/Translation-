#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sample.h"

char* create_payload(const char* text, const char* source, const char* target) {
    char* payload = malloc(2560);
    snprintf(payload, 2560, 
             "{\"SourceText\":\"%s\",\"Source\":\"%s\",\"Target\":\"%s\",\"ProjectId\":0}",
             text, source, target);
    return payload;
}

int main(int argc, char *argv[]) {
    const char *SECRET_ID = "公钥";
    const char *SECRET_KEY = "密钥";
    const char *TOKEN = "";
    const char *source_text = "默认";
    if (argc != 0){
        source_text = argv[1];
    }
    const char *source_lang = "en";
    const char *target_lang = "zh";

    const char *service = "tmt";
    const char *host = "tmt.tencentcloudapi.com";
    const char *region = "ap-beijing";
    const char *action = "TextTranslate";
    const char *version = "2018-03-21";

    int64_t timestamp = time(NULL);
    char date[20] = {0};
    get_utc_date(timestamp, date, sizeof(date));

    const char *http_request_method = "POST";
    const char *canonical_uri = "/";
    const char *canonical_query_string = "";
    char canonical_headers[256] = {"content-type:application/json; charset=utf-8\nhost:"};
    strcat(canonical_headers, host);
    strcat(canonical_headers, "\nx-tc-action:");
    char value[100] = {0};
    lowercase(action, value);
    strcat(canonical_headers, value);
    strcat(canonical_headers, "\n");
    const char *signed_headers = "content-type;host;x-tc-action";
    char* payload = create_payload(source_text, source_lang, target_lang);
    char hashed_request_payload[100] = {0};
    sha256_hex(payload, hashed_request_payload);

    char canonical_request[4096] = {0};
    sprintf(canonical_request, "%s\n%s\n%s\n%s\n%s\n%s", http_request_method, canonical_uri,
            canonical_query_string, canonical_headers, signed_headers, hashed_request_payload);

    const char *algorithm = "TC3-HMAC-SHA256";
    char request_timestamp[16] = {0};
    sprintf(request_timestamp, "%ld", timestamp);
    char credential_scope[64] = {0};
    sprintf(credential_scope, "%s/%s/tc3_request", date, service);
    char hashed_canonical_request[100] = {0};
    sha256_hex(canonical_request, hashed_canonical_request);
    char string_to_sign[1024] = {0};
    sprintf(string_to_sign, "%s\n%s\n%s\n%s", algorithm, request_timestamp,
            credential_scope, hashed_canonical_request);

    char k_key[64] = {0};
    sprintf(k_key, "%s%s", "TC3", SECRET_KEY);
    unsigned char k_date[64] = {0};
    size_t output_len = 64;
    hmac_sha256(k_key, (int)strlen(k_key), 
               date, (int)strlen(date), 
               k_date, &output_len);
    
    unsigned char k_service[64] = {0};
    output_len = 64;
    
    hmac_sha256((const char*)k_date, output_len, 
               service, (int)strlen(service), 
               k_service, &output_len);
    
    unsigned char k_signing[64] = {0};
    output_len = 64;
    

    hmac_sha256((const char*)k_service, output_len, 
               "tc3_request", (int)strlen("tc3_request"), 
               k_signing, &output_len);
    
    unsigned char k_hmac_sha_sign[64] = {0};
    output_len = 64;
    

    hmac_sha256((const char*)k_signing, output_len, 
               string_to_sign, (int)strlen(string_to_sign), 
               k_hmac_sha_sign, &output_len);

    char signature[128] = {0};
    hex_encode((const char*)k_hmac_sha_sign, output_len, signature);

    char authorization[512] = {0};
    sprintf(authorization, "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
            algorithm, SECRET_ID, credential_scope, signed_headers, signature);


    char url[100] = {0};
    sprintf(url, "https://%s", host);
    char authorizationHeader[2048] = {0};
    sprintf(authorizationHeader, "Authorization: %s", authorization);
    char hostHeader[128] = {0};
    sprintf(hostHeader, "Host: %s", host);
    char actionHeader[128] = {0};
    sprintf(actionHeader, "X-TC-Action: %s", action);
    char timestampHeader[128] = {0};
    sprintf(timestampHeader, "X-TC-Timestamp: %s", request_timestamp);
    char versionHeader[128] = {0};
    sprintf(versionHeader, "X-TC-Version: %s", version);
    char regionHeader[128] = {0};
    sprintf(regionHeader, "X-TC-Region: %s", region);
    char tokenHeader[128] = {0};
    sprintf(tokenHeader, "X-TC-Token: %s", TOKEN);

    struct WriteData resData = {0};
    resData.response = malloc(4096);
    resData.size = 0;
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, authorizationHeader);
        headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");
        headers = curl_slist_append(headers, hostHeader);
        headers = curl_slist_append(headers, actionHeader);
        headers = curl_slist_append(headers, timestampHeader);
        headers = curl_slist_append(headers, versionHeader);
        headers = curl_slist_append(headers, regionHeader);
        headers = curl_slist_append(headers, tokenHeader);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resData);
        
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            printf("%s\n", resData.response);
        } else {
            printf("Request failed. Error code: %d\n", res);
        }
        
        curl_slist_free_all(headers);
        free(resData.response);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(payload);
    return 0;
}
