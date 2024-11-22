/* AWS V4 Signature implementation
 *
 * This file contains the modularized source code for accepting a given HTTP
 * request as ngx_http_request_t and modifiying it to introduce the
 * Authorization header in compliance with the AWS V4 spec. The IAM access
 * key and the signing key (not to be confused with the secret key) along
 * with it's scope are taken as inputs.
 *
 * The actual nginx module binding code is not present in this file. This file
 * is meant to serve as an "AWS Signing SDK for nginx".
 *
 * Maintainer/contributor rules
 *
 * (1) All functions here need to be static and inline.
 * (2) Every function must have it's own set of unit tests.
 * (3) The code must be written in a thread-safe manner. This is usually not
 *     a problem with standard nginx functions. However, care must be taken
 *     when using very old C functions such as strtok, gmtime, etc. etc.
 *     Always use the _r variants of such functions
 * (4) All heap allocation must be done using ngx_pool_t instead of malloc
 */

#ifndef __NGX_HTTP_AWS_FUNCTIONS_INTERNAL__H__
#define __NGX_HTTP_AWS_FUNCTIONS_INTERNAL__H__

#include <time.h>
#include <ngx_times.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "crypto_helper.h"

#define AMZ_DATE_MAX_LEN 20
#define STRING_TO_SIGN_LENGTH 3000

typedef ngx_keyval_t header_pair_t;

struct AwsCanonicalRequestDetails {
    ngx_str_t       *canon_request;
    ngx_str_t       *signed_header_names;
    ngx_array_t     *header_list; // list of header_pair_t
};

struct AwsCanonicalHeaderDetails {
    ngx_str_t       *canon_header_str;
    ngx_str_t       *signed_header_names;
    ngx_array_t     *header_list; // list of header_pair_t
};

struct AwsSignedRequestDetails {
    const ngx_str_t *signature;
    const ngx_str_t *signed_header_names;
    ngx_array_t     *header_list; // list of header_pair_t
};


// mainly useful to avoid having to full instantiate request structures for
// tests...
#define safe_ngx_log_error(r, ...)                                      \
    if (r->connection) {                                                \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, __VA_ARGS__); \
    }


static const ngx_str_t EMPTY_STRING_SHA256 = ngx_string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
static const ngx_str_t EMPTY_STRING = ngx_null_string;
static const ngx_str_t AMZ_HASH_HEADER = ngx_string("x-amz-content-sha256");
static const ngx_str_t AMZ_DATE_HEADER = ngx_string("x-amz-date");
static const ngx_str_t HOST_HEADER = ngx_string("host");
static const ngx_str_t AUTHZ_HEADER = ngx_string("authorization");


static inline char* __CHAR_PTR_U(u_char* ptr)
{
    return (char*)ptr;
}


static inline const char* __CONST_CHAR_PTR_U(const u_char* ptr)
{
    return (const char*)ptr;
}


static inline const ngx_str_t* ngx_http_aws_auth__compute_request_time(ngx_http_request_t *r, const time_t *timep)
{
    ngx_str_t *const retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    retval->data = ngx_palloc(r->pool, AMZ_DATE_MAX_LEN);
    struct tm *tm_p = ngx_palloc(r->pool, sizeof(struct tm));
    gmtime_r(timep, tm_p);
    retval->len = strftime(__CHAR_PTR_U(retval->data), AMZ_DATE_MAX_LEN - 1, "%Y%m%dT%H%M%SZ", tm_p);
    return retval;
}


static inline int ngx_http_aws_auth__cmp_hnames(const void *one, const void *two)
{
    header_pair_t *first, *second;
    int ret;
    first  = (header_pair_t *) one;
    second = (header_pair_t *) two;
    ret = ngx_strncmp(first->key.data, second->key.data, ngx_min(first->key.len, second->key.len));
    if (ret != 0){
        return ret;
    } else {
        return (first->key.len - second->key.len);
    }
}


static inline const ngx_str_t* ngx_http_aws_auth__canonize_query_string(ngx_http_request_t *r)
{
    u_char *p, *ampersand, *equal, *last;
    size_t i, len;
    ngx_str_t *retval = ngx_palloc(r->pool, sizeof(ngx_str_t));

    header_pair_t *qs_arg;
    ngx_array_t *query_string_args = ngx_array_create(r->pool, 0, sizeof(header_pair_t));

    if (r->args.len == 0) {
        return &EMPTY_STRING;
    }

    p = r->args.data;
    last = p + r->args.len;

    for ( /* void */ ; p < last; p++) {
        qs_arg = ngx_array_push(query_string_args);

        ampersand = ngx_strlchr(p, last, '&');
        if (ampersand == NULL) {
            ampersand = last;
        }

        equal = ngx_strlchr(p, last, '=');
        if ((equal == NULL) || (equal > ampersand)) {
            equal = ampersand;
        }

        len = equal - p;
        qs_arg->key.data = ngx_palloc(r->pool, len*3);
        qs_arg->key.len = (u_char *)ngx_escape_uri(qs_arg->key.data, p, len, NGX_ESCAPE_ARGS) - qs_arg->key.data;


        len = ampersand - equal;
        if(len > 0 ) {
            qs_arg->value.data = ngx_palloc(r->pool, len*3);
            qs_arg->value.len = (u_char *)ngx_escape_uri(qs_arg->value.data, equal+1, len-1, NGX_ESCAPE_ARGS) - qs_arg->value.data;
        } else {
            qs_arg->value = EMPTY_STRING;
        }

        p = ampersand;
    }

    ngx_qsort(query_string_args->elts, (size_t) query_string_args->nelts,
        sizeof(header_pair_t), ngx_http_aws_auth__cmp_hnames);

    retval->data = ngx_palloc(r->pool, r->args.len*3 + query_string_args->nelts*2);
    retval->len = 0;

    for(i = 0; i < query_string_args->nelts; i++) {
        qs_arg = &((header_pair_t*)query_string_args->elts)[i];

        ngx_memcpy(retval->data + retval->len, qs_arg->key.data, qs_arg->key.len);
        retval->len += qs_arg->key.len;

        *(retval->data + retval->len) = '=';
        retval->len++;

        ngx_memcpy(retval->data + retval->len, qs_arg->value.data, qs_arg->value.len);
        retval->len += qs_arg->value.len;

        *(retval->data + retval->len) = '&';
        retval->len++;
    }
    retval->len--;

    safe_ngx_log_error(r, "canonical qs constructed is %V", retval);

    return retval;
}


static inline const ngx_str_t* ngx_http_aws_auth__host_from_bucket(ngx_http_request_t *r,
    const ngx_str_t *s3_bucket)
{
    static const char HOST_PATTERN[] = ".s3.amazonaws.com";
    ngx_str_t *host;

    host = ngx_palloc(r->pool, sizeof(ngx_str_t));
    host->len = s3_bucket->len + sizeof(HOST_PATTERN) + 1;
    host->data = ngx_palloc(r->pool, host->len);
    host->len = ngx_snprintf(host->data, host->len, "%V%s", s3_bucket, HOST_PATTERN) - host->data;

    return host;
}


static inline struct AwsCanonicalHeaderDetails ngx_http_aws_auth__canonize_headers(
    ngx_http_request_t *r,
    const ngx_str_t *s3_bucket, const ngx_str_t *amz_date,
    const ngx_str_t *content_hash,
    const ngx_str_t *s3_endpoint)
{
    size_t header_names_size = 1, header_nameval_size = 1;
    size_t i, used;
    u_char *buf_progress;
    struct AwsCanonicalHeaderDetails retval;

    ngx_array_t *settable_header_array = ngx_array_create(r->pool, 3, sizeof(header_pair_t));
    header_pair_t *header_ptr;

    header_ptr = ngx_array_push(settable_header_array);
    header_ptr->key = AMZ_HASH_HEADER;
    header_ptr->value = *content_hash;

    header_ptr = ngx_array_push(settable_header_array);
    header_ptr->key = AMZ_DATE_HEADER;
    header_ptr->value = *amz_date;

    header_ptr = ngx_array_push(settable_header_array);
    header_ptr->key = HOST_HEADER;
    header_ptr->value.len = s3_bucket->len + s3_endpoint->len + 2;
    header_ptr->value.data = ngx_palloc(r->pool, header_ptr->value.len);
    header_ptr->value.len = ngx_snprintf(header_ptr->value.data, header_ptr->value.len, "%V.%V", s3_bucket, s3_endpoint) - header_ptr->value.data;

    ngx_qsort(settable_header_array->elts, (size_t) settable_header_array->nelts,
        sizeof(header_pair_t), ngx_http_aws_auth__cmp_hnames);
    retval.header_list = settable_header_array;

    for(i = 0; i < settable_header_array->nelts; i++) {
        header_names_size += ((header_pair_t*)settable_header_array->elts)[i].key.len + 1;
        header_nameval_size += ((header_pair_t*)settable_header_array->elts)[i].key.len + 1;
        header_nameval_size += ((header_pair_t*)settable_header_array->elts)[i].value.len + 2;
    }

    /* make canonical headers string */
    retval.canon_header_str = ngx_palloc(r->pool, sizeof(ngx_str_t));
    retval.canon_header_str->data = ngx_palloc(r->pool, header_nameval_size);

    for(i = 0, used = 0, buf_progress = retval.canon_header_str->data;
        i < settable_header_array->nelts;
        i++, used = buf_progress - retval.canon_header_str->data) {
        buf_progress = ngx_snprintf(buf_progress, header_nameval_size - used, "%V:%V\n",
            & ((header_pair_t*)settable_header_array->elts)[i].key,
            & ((header_pair_t*)settable_header_array->elts)[i].value);
    }
    retval.canon_header_str->len = used;

    /* make signed headers */
    retval.signed_header_names = ngx_palloc(r->pool, sizeof(ngx_str_t));
    retval.signed_header_names->data = ngx_palloc(r->pool, header_names_size);

    for(i = 0, used = 0, buf_progress = retval.signed_header_names->data;
        i < settable_header_array->nelts;
        i++, used = buf_progress - retval.signed_header_names->data) {
        buf_progress = ngx_snprintf(buf_progress, header_names_size - used, "%V;",
            & ((header_pair_t*)settable_header_array->elts)[i].key);
    }
    used--;
    retval.signed_header_names->len = used;
    retval.signed_header_names->data[used] = 0;

    return retval;
}


static inline const ngx_str_t* ngx_http_aws_auth__request_body_hash(ngx_http_request_t *r)
{
    /* TODO: support cases involving non-empty body */
    return &EMPTY_STRING_SHA256;
}


// AWS wants a peculiar kind of URI-encoding: they want RFC 3986, except that
// slashes shouldn't be encoded...
// this function is a light wrapper around ngx_escape_uri that does exactly that
// modifies the source in place if it needs to be escaped
// see http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
static inline void ngx_http_aws_auth__escape_uri(ngx_http_request_t *r, ngx_str_t* src)
{
    u_char *escaped_data;
    u_int escaped_data_len, escaped_data_with_slashes_len, i, j;
    uintptr_t escaped_count, slashes_count = 0;

    // first, we need to know how many characters need to be escaped
    escaped_count = ngx_escape_uri(NULL, src->data, src->len, NGX_ESCAPE_URI_COMPONENT);
    // except slashes should not be escaped...
    if (escaped_count > 0) {
        for (i = 0; i < src->len; i++) {
            if (src->data[i] == '/') {
                slashes_count++;
            }
        }
    }

    if (escaped_count == slashes_count) {
        // nothing to do! nothing but slashes escaped (if even that)
        return;
    }

    // each escaped character is replaced by 3 characters
    escaped_data_len = src->len + escaped_count * 2;
    escaped_data = ngx_palloc(r->pool, escaped_data_len);
    ngx_escape_uri(escaped_data, src->data, src->len, NGX_ESCAPE_URI_COMPONENT);

    // now we need to go back and re-replace each occurrence of %2F with a slash
    escaped_data_with_slashes_len = src->len + (escaped_count - slashes_count) * 2;
    if (slashes_count > 0) {
        for (i = 0, j = 0; i < escaped_data_with_slashes_len; i++) {
            if (j < escaped_data_len - 2 && strncmp((char*) (escaped_data + j), "%2F", 3) == 0) {
                escaped_data[i] = '/';
                j += 3;
            } else {
                escaped_data[i] = escaped_data[j];
                j++;
            }
        }

        src->len = escaped_data_with_slashes_len;
    } else {
        // no slashes
        src->len = escaped_data_len;
    }

  src->data = escaped_data;
}


static inline const ngx_str_t* ngx_http_aws_auth__canon_url(ngx_http_request_t *r)
{
    ngx_str_t *retval;
    const u_char *uri_data;
    u_int uri_len;

    if(r->args.len == 0) {
        uri_data = r->uri.data;
        uri_len = r->uri.len;
    } else {
        uri_data = r->uri_start;
        uri_len = r->args_start - r->uri_start - 1;
    }

    // we need to copy that data to not modify the request for other modules
    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    retval->data = ngx_palloc(r->pool, uri_len);
    ngx_memcpy(retval->data, uri_data, uri_len);
    retval->len = uri_len;

    safe_ngx_log_error(r, "canonical url extracted before URI encoding is %V", retval);

    // then URI-encode it per RFC 3986
    ngx_http_aws_auth__escape_uri(r, retval);
    safe_ngx_log_error(r, "canonical url extracted after URI encoding is %V", retval);

    return retval;
}


static inline struct AwsCanonicalRequestDetails ngx_http_aws_auth__make_canonical_request(ngx_http_request_t *r,
    const ngx_str_t *s3_bucket_name, const ngx_str_t *amz_date,
    const ngx_str_t *s3_endpoint, const ngx_flag_t *convert_head)
{
    struct AwsCanonicalRequestDetails retval;

    // canonize query string
    const ngx_str_t *canon_qs = ngx_http_aws_auth__canonize_query_string(r);

    // compute request body hash
    const ngx_str_t *request_body_hash = ngx_http_aws_auth__request_body_hash(r);

    const struct AwsCanonicalHeaderDetails canon_headers =
        ngx_http_aws_auth__canonize_headers(r, s3_bucket_name, amz_date, request_body_hash, s3_endpoint);
    retval.signed_header_names = canon_headers.signed_header_names;

    const ngx_str_t *http_method = &(r->method_name);
    if (r->method == NGX_HTTP_HEAD && *convert_head) {
        static ngx_str_t get_method = ngx_string("GET");
        http_method = &get_method;
    }

    const ngx_str_t *url = ngx_http_aws_auth__canon_url(r);

    retval.canon_request = ngx_palloc(r->pool, sizeof(ngx_str_t));
    retval.canon_request->len = 10000;
    retval.canon_request->data = ngx_palloc(r->pool, retval.canon_request->len);

    retval.canon_request->len = ngx_snprintf(retval.canon_request->data, retval.canon_request->len, "%V\n%V\n%V\n%V\n%V\n%V",
        http_method, url, canon_qs, canon_headers.canon_header_str,
        canon_headers.signed_header_names, request_body_hash) - retval.canon_request->data;
    retval.header_list = canon_headers.header_list;

    safe_ngx_log_error(r, "canonical request is %V", retval.canon_request);

    return retval;
}


static inline const ngx_str_t* ngx_http_aws_auth__string_to_sign(ngx_http_request_t *r,
    const ngx_str_t *key_scope,	const ngx_str_t *date, const ngx_str_t *canon_request_hash)
{
    ngx_str_t *retval = ngx_palloc(r->pool, sizeof(ngx_str_t));

    retval->len = STRING_TO_SIGN_LENGTH;
    retval->data = ngx_palloc(r->pool, retval->len);
    retval->len = ngx_snprintf(retval->data, retval->len, "AWS4-HMAC-SHA256\n%V\n%V\n%V",
        date, key_scope, canon_request_hash) - retval->data ;

    return retval;
}


static inline const ngx_str_t* ngx_http_aws_auth__make_auth_token(ngx_http_request_t *r,
    const ngx_str_t *signature, const ngx_str_t *signed_header_names,
    const ngx_str_t *access_key, const ngx_str_t *key_scope)
{

    const char FMT_STRING[] = "AWS4-HMAC-SHA256 Credential=%V/%V,SignedHeaders=%V,Signature=%V";
    ngx_str_t *authz;

    authz = ngx_palloc(r->pool, sizeof(ngx_str_t));
    authz->len = access_key->len + key_scope->len + signed_header_names->len
        + signature->len + sizeof(FMT_STRING);
    authz->data = ngx_palloc(r->pool, authz->len);
    authz->len = ngx_snprintf(authz->data, authz->len, FMT_STRING,
        access_key, key_scope, signed_header_names, signature) - authz->data;
    return authz;
}


static inline struct AwsSignedRequestDetails ngx_http_aws_auth__compute_signature(ngx_http_request_t *r,
    const ngx_str_t *signing_key, const ngx_str_t *key_scope, const ngx_str_t *s3_bucket_name,
    const ngx_str_t *s3_endpoint, const ngx_flag_t *convert_head)
{
    struct AwsSignedRequestDetails retval;

    const ngx_str_t *date = ngx_http_aws_auth__compute_request_time(r, &r->start_sec);
    const struct AwsCanonicalRequestDetails canon_request =
        ngx_http_aws_auth__make_canonical_request(r, s3_bucket_name, date, s3_endpoint, convert_head);
    const ngx_str_t *canon_request_hash = ngx_http_aws_auth__hash_sha256(r, canon_request.canon_request);

    // get string to sign
    const ngx_str_t *string_to_sign = ngx_http_aws_auth__string_to_sign(r, key_scope, date, canon_request_hash);

    // generate signature
    const ngx_str_t *signature = ngx_http_aws_auth__sign_sha256_hex(r, string_to_sign, signing_key);

    retval.signature = signature;
    retval.signed_header_names = canon_request.signed_header_names;
    retval.header_list = canon_request.header_list;
    return retval;
}


static ngx_int_t
ngx_http_aws_auth__generate_signing_key(ngx_http_request_t *r,
    const ngx_str_t *secret_key, const ngx_str_t *region,
    ngx_str_t *signature_key, ngx_str_t *key_scope)
{
    u_char      date_stamp[9];
    ngx_tm_t    tm;
    time_t      now;
    size_t      key_scope_len;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generate_signing_key: secret_key.len=%uz, region.len=%uz, convert_head=%d",
                   secret_key->len, region->len, 1);

    now = ngx_time();
    ngx_libc_gmtime(now, &tm);
    ngx_snprintf(date_stamp, sizeof(date_stamp), "%04d%02d%02d",
                tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday);
    date_stamp[8] = '\0'; // 确保以 NULL 终止

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generate_signing_key: date_stamp=%s", date_stamp);

    ngx_str_t service = ngx_string("s3");
    ngx_str_t aws4_request = ngx_string("aws4_request");

    key_scope_len = ngx_strlen(date_stamp) + 1 + region->len + 1 +
                    service.len + 1 + aws4_request.len;

    key_scope->data = ngx_pnalloc(r->pool, key_scope_len + 1);
    if (key_scope->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "generate_signing_key: failed to allocate memory for key_scope");
        return NGX_ERROR;
    }

    key_scope->len = ngx_snprintf(key_scope->data, key_scope_len + 1, "%s/%V/%V/%V",
                                  date_stamp, region, &service, &aws4_request)
                     - key_scope->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generate_signing_key: key_scope=%V", key_scope);

    size_t kSecret_len = 4 + secret_key->len;
    u_char *kSecret = ngx_pnalloc(r->pool, kSecret_len);
    if (kSecret == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "generate_signing_key: failed to allocate memory for kSecret");
        return NGX_ERROR;
    }

    ngx_memcpy(kSecret, "AWS4", 4);
    ngx_memcpy(kSecret + 4, secret_key->data, secret_key->len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generate_signing_key: kSecret prepared (length=%uz)", kSecret_len);

    ngx_str_t data_to_sign[] = {
        {8, date_stamp},          // date_stamp
        *region,                  // region
        service,                  // service
        aws4_request              // "aws4_request"
    };

    u_char     *key = kSecret;
    size_t      key_len = kSecret_len;

    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len;

    HMAC_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx_old;
    ctx = &ctx_old;
    HMAC_CTX_init(ctx);
#else
    ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "generate_signing_key: failed to create HMAC_CTX");
        return NGX_ERROR;
    }
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generate_signing_key: starting HMAC calculations");

    for (int i = 0; i < 4; i++) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "generate_signing_key: HMAC step %d", i + 1);

        if (HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL) != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "generate_signing_key: HMAC_Init_ex failed at step %d", i + 1);
            goto hmac_fail;
        }

        if (HMAC_Update(ctx, data_to_sign[i].data, data_to_sign[i].len) != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "generate_signing_key: HMAC_Update failed at step %d", i + 1);
            goto hmac_fail;
        }

        if (HMAC_Final(ctx, hmac_result, &hmac_len) != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "generate_signing_key: HMAC_Final failed at step %d", i + 1);
            goto hmac_fail;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "generate_signing_key: HMAC step %d completed, result length=%u",
                       i + 1, hmac_len);

        key = hmac_result;
        key_len = hmac_len;

        if (HMAC_Init_ex(ctx, NULL, 0, NULL, NULL) != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "generate_signing_key: HMAC_Init_ex reset failed after step %d", i + 1);
            goto hmac_fail;
        }
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    signature_key->data = ngx_pnalloc(r->pool, hmac_len);
    if (signature_key->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "generate_signing_key: failed to allocate memory for signature_key");
        return NGX_ERROR;
    }

    signature_key->len = hmac_len;
    ngx_memcpy(signature_key->data, hmac_result, hmac_len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generate_signing_key: signature_key generated (len=%uz)", signature_key->len);

    return NGX_OK;

hmac_fail:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(ctx);
#else
    HMAC_CTX_free(ctx);
#endif
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "generate_signing_key: HMAC computation failed");
    return NGX_ERROR;
}


// list of header_pair_t
static inline const ngx_array_t* ngx_http_aws_auth__sign(ngx_http_request_t *r,
    const ngx_str_t *access_key, const ngx_str_t *signing_key, const ngx_str_t *key_scope,
    const ngx_str_t *secret_key, const ngx_str_t *region, const ngx_str_t *s3_bucket_name,
    const ngx_str_t *s3_endpoint, const ngx_flag_t *convert_head)
{
    ngx_str_t local_signing_key;
    ngx_str_t local_key_scope;
    const ngx_str_t *used_signing_key = signing_key;
    const ngx_str_t *used_key_scope = key_scope;

    if (signing_key == NULL || signing_key->len == 0 || signing_key->data == NULL) {
        ngx_memzero(&local_signing_key, sizeof(ngx_str_t));
        ngx_memzero(&local_key_scope, sizeof(ngx_str_t));

        ngx_http_aws_auth__generate_signing_key(r, secret_key, region, &local_signing_key, &local_key_scope);

        used_signing_key = &local_signing_key;
        used_key_scope = &local_key_scope;
    }

    const struct AwsSignedRequestDetails signature_details = ngx_http_aws_auth__compute_signature(r, used_signing_key, used_key_scope, s3_bucket_name, s3_endpoint, convert_head);


    const ngx_str_t *auth_header_value = ngx_http_aws_auth__make_auth_token(r, signature_details.signature,
                                            signature_details.signed_header_names, access_key, key_scope);

    header_pair_t *header_ptr;
    header_ptr = ngx_array_push(signature_details.header_list);
    header_ptr->key = AUTHZ_HEADER;
    header_ptr->value = *auth_header_value;

    return signature_details.header_list;
}

#endif
