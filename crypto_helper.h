#ifndef __NGX_HTTP_AWS_AUTH__CRYPTO_HELPER__
#define __NGX_HTTP_AWS_AUTH__CRYPTO_HELPER__


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_str_t* ngx_http_aws_auth__hash_sha256(ngx_http_request_t *r, const ngx_str_t *blob);
ngx_str_t* ngx_http_aws_auth__sign_sha256_hex(ngx_http_request_t *r, const ngx_str_t *blob, const ngx_str_t *signing_key);

#endif
