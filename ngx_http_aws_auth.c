#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "aws_functions.h"


#define AWS_S3_VARIABLE "s3_auth_token"
#define AWS_DATE_VARIABLE "aws_date"


static void* ngx_http_aws_auth_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_aws_auth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_aws_auth_sign(ngx_http_request_t *r);
static ngx_int_t ngx_http_aws_auth_req_init(ngx_conf_t *cf);


typedef struct {
    ngx_flag_t                enable;
    ngx_flag_t                convert_head;

    ngx_array_t              *bypass;

    ngx_str_t                 access_key;
    ngx_str_t                 key_scope;
    ngx_str_t                 signing_key;
    ngx_str_t                 secret_key;
    ngx_str_t                 region;
    ngx_str_t                 signing_key_decoded;
    ngx_str_t                 endpoint;
    ngx_str_t                 bucket;

    ngx_http_complex_value_t *host;
    ngx_http_complex_value_t *uri;
} ngx_http_aws_auth_conf_t;


static ngx_command_t  ngx_http_aws_auth_commands[] = {
    { ngx_string("aws_auth_access_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, access_key),
      NULL },

    { ngx_string("aws_auth_key_scope"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, key_scope),
      NULL },

    { ngx_string("aws_auth_signing_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, signing_key),
      NULL },

    { ngx_string("aws_auth_secret_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, secret_key),
      NULL },

    { ngx_string("aws_auth_region"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, region),
      NULL },

    { ngx_string("aws_auth_endpoint"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, endpoint),
      NULL },

    { ngx_string("aws_auth_bucket"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, bucket),
      NULL },

    { ngx_string("aws_auth_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, host),
      NULL },

    { ngx_string("aws_auth_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, uri),
      NULL },

    { ngx_string("aws_auth_convert_head"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, convert_head),
      NULL },

    { ngx_string("aws_auth_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, bypass),
      NULL },

    { ngx_string("aws_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_aws_auth_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_aws_auth_req_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_aws_auth_create_loc_conf,     /* create location configuration */
    ngx_http_aws_auth_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_aws_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_aws_auth_module_ctx,         /* module context */
    ngx_http_aws_auth_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_aws_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_aws_auth_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_aws_auth_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->convert_head = NGX_CONF_UNSET;

    conf->host = NGX_CONF_UNSET_PTR;
    conf->uri = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_aws_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_aws_auth_conf_t *prev = parent;
    ngx_http_aws_auth_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->convert_head, prev->convert_head, 1);

    ngx_conf_merge_str_value(conf->access_key, prev->access_key, "");
    ngx_conf_merge_str_value(conf->key_scope, prev->key_scope, "");
    ngx_conf_merge_str_value(conf->signing_key, prev->signing_key, "");
    ngx_conf_merge_str_value(conf->secret_key, prev->secret_key, "");
    ngx_conf_merge_str_value(conf->region, prev->region, "us-east-1");
    ngx_conf_merge_str_value(conf->endpoint, prev->endpoint,
        "s3.amazonaws.com");
    ngx_conf_merge_str_value(conf->bucket, prev->bucket, "");

    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_ptr_value(conf->host, prev->host, NULL);
    ngx_conf_merge_ptr_value(conf->uri, prev->uri, NULL);

    if (conf->signing_key.len != 0) {
        if (conf->signing_key_decoded.data == NULL) {
            conf->signing_key_decoded.data = ngx_pcalloc(cf->pool, 100);
            if (conf->signing_key_decoded.data == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->signing_key.len > 64) {
            return NGX_CONF_ERROR;
        } else {
            ngx_decode_base64(&conf->signing_key_decoded, &conf->signing_key);
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_aws_auth_sign(ngx_http_request_t *r)
{
    ngx_http_aws_auth_conf_t *conf = ngx_http_get_module_loc_conf(r,
        ngx_http_aws_auth_module);
    ngx_table_elt_t          *h;
    header_pair_t            *hv;
    ngx_uint_t                i, j;
    ngx_list_part_t          *part = &r->headers_in.headers.part;
    ngx_table_elt_t          *headers = part->elts;

    if (!conf->enable) {
        /* return directly if module is not enable */
        return NGX_DECLINED;
    }

    switch (ngx_http_test_predicates(r, conf->bypass)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        return NGX_DECLINED;

    default: /* NGX_OK */
        break;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        /* We do not wish to support anything with a body as signing for a body is unimplemented */
        /* Just skip the processing operation without returning an error */
        return NGX_DECLINED;
    }

    const ngx_array_t* headers_out = ngx_http_aws_auth__sign(r,
        &conf->access_key, &conf->signing_key_decoded, &conf->key_scope,
        &conf->secret_key, &conf->region, &conf->bucket, &conf->endpoint,
        conf->host, &conf->convert_head);

    for ( /* void */ ; part != NULL; part = part->next) {
        for (i = 0; i < part->nelts; i++) {
            /* Check Authorization header */
            if (headers[i].hash != 0 &&
                headers[i].key.len == AUTHZ_HEADER.len &&
                ngx_strcasecmp(headers[i].key.data, AUTHZ_HEADER.data) == 0)
            {
                /* Remove Authorization header */
                for (j = i; j < part->nelts - 1; j++) {
                    headers[j] = headers[j + 1];
                }
                part->nelts--;
                i--;
                continue;
            }

            /* Check X-Amz-Date header */
            if (headers[i].hash != 0 &&
                headers[i].key.len == AMZ_DATE_HEADER.len &&
                ngx_strcasecmp(headers[i].key.data, AMZ_DATE_HEADER.data) == 0)
            {
                /* Remove X-Amz-Date header */
                for (j = i; j < part->nelts - 1; j++) {
                    headers[j] = headers[j + 1];
                }
                part->nelts--;
                i--;
                continue;
            }

            /* Check X-Amz-Content-Sha256 header */
            if (headers[i].hash != 0 &&
                headers[i].key.len == AMZ_HASH_HEADER.len &&
                ngx_strcasecmp(headers[i].key.data, AMZ_HASH_HEADER.data) == 0)
            {
                /* Remove X-Amz-Content-Sha256 header */
                for (j = i; j < part->nelts - 1; j++) {
                    headers[j] = headers[j + 1];
                }
                part->nelts--;
                i--;
                continue;
            }

            /* Do not change host header here, let's handle this in the proxy module */

        }
    }

    for (i = 0; i < headers_out->nelts; i++) {
        hv = (header_pair_t*)((u_char *) headers_out->elts
            + headers_out->size * i);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "header name %s, value %s", hv->key.data, hv->value.data);

        if (ngx_strncmp(hv->key.data, HOST_HEADER.data, hv->key.len) == 0) {
            /* host header is controlled by proxy pass directive and hence
               cannot be set by our module */
            continue;
        }

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->key = hv->key;
        h->lowcase_key = hv->key.data; /* We ensure that header names are already lowercased */
        h->value = hv->value;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_req_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_aws_auth_sign;

    return NGX_OK;
}
/*
 * vim: ts=4 sw=4 et
 */

