#ifndef __NGX_HTTP_PROXY_AUTH_AWS__CRYPTO_HELPER__
#define __NGX_HTTP_PROXY_AUTH_AWS__CRYPTO_HELPER__


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_str_t* ngx_http_proxy_auth_aws__hash_sha256(ngx_http_request_t *r,
	const ngx_str_t *blob);
ngx_str_t* ngx_http_proxy_auth_aws__sign_sha256(ngx_http_request_t *r,
	const ngx_str_t *blob, const ngx_str_t *signing_key);
ngx_str_t* ngx_http_proxy_auth_aws__sign_sha256_hex(ngx_http_request_t *r,
	const ngx_str_t *blob, const ngx_str_t *signing_key);

#endif
