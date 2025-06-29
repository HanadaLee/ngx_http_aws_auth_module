# AWS proxy module

This nginx module can proxy requests to authenticated S3 backends using Amazon's
V4 authentication API. The first version of this module was written for the V2
authentication protocol and can be found in the *AuthV2* branch.

This fork changes the processing phase to NGX_HTTP_PRECONTENT_PHASE, so subrequests can also use this module to generate authentication headers normally. In addition, some instructions and functions are added according to actual usage needs.

## License
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license

## Usage example

Implements proxying of authenticated requests to S3.

```nginx
  server {
    listen     8000;

    # proxy_auth_aws_convert_head is on by default.
    # If you set `proxy_cache_convert_head` to off, or the `proxy_cache` function is not enabled, please also set `proxy_auth_aws_convert_head` to off. Otherwise, the HEAD request may be intercepted.
    # proxy_cache_convert_head off;
    # proxy_auth_aws_convert_head off;

    # Determine whether to append an authentication header based on the values ​​of multiple variables.
    # proxy_auth_aws_bypass $http_no_s3_auth $arg_no_s3_auth $cookie_no_s3_auth $http_authorization;

    location / {
      proxy_auth_aws on;
      proxy_auth_aws_access_key your_aws_access_key; # Example AKIDEXAMPLE
      proxy_auth_aws_key_scope scope_of_generated_signing_key; #Example 20150830/us-east-1/service/aws4_request
      proxy_auth_aws_signing_key signing_key_generated_using_script; #Example L4vRLWAO92X5L3Sqk5QydUSdB0nC9+1wfqLMOKLbRp4=
      proxy_auth_aws_bucket your_s3_bucket;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com;
    }

    # This is an example that does not use the server root for the proxy root
    location /myfiles {

      rewrite /myfiles/(.*) /$1 break;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com/$1;

      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_key_scope scope_of_generated_signing_key;
      proxy_auth_aws_signing_key signing_key_generated_using_script;
      proxy_auth_aws_bucket your_s3_bucket;
    }

    # This is an example that use specific s3 endpoint, default endpoint is s3.amazonaws.com
    location /s3_beijing {

      rewrite /s3_beijing/(.*) /$1 break;
      proxy_pass http://your_s3_bucket.s3.cn-north-1.amazonaws.com.cn/$1;

      proxy_auth_aws on;
      proxy_auth_aws_endpoint s3.cn-north-1.amazonaws.com.cn;
      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_key_scope scope_of_generated_signing_key;
      proxy_auth_aws_signing_key signing_key_generated_using_script;
      proxy_auth_aws_bucket your_s3_bucket;
    }

    # This is an example that specific upstream host and uri
    # Be careful not to use proxy_auth_aws_host and proxy_auth_aws_bucket + proxy_auth_aws_endpoint at the same time, proxy_auth_aws_bucket + proxy_auth_aws_endpoint will have higher priority.
    location /s3_beijing_2 {
      set $upstream_host your_s3_bucket.s3.cn-north-1.amazonaws.com.cn;
      set $upstream_uri /test.txt;
      proxy_pass http://$upstream_host$upstream_uri;
      proxy_auth_aws on;
      proxy_auth_aws_host $upstream_host;
      proxy_auth_aws_uri $upstream_uri;
      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_key_scope scope_of_generated_signing_key;
      proxy_auth_aws_signing_key signing_key_generated_using_script;
    }

    # Security warning: Placing the secret key in the nginx configuration is unsafe. Please give priority to using the script mentioned below to generate and regularly update the signing key. Only use this solution as a last resort.
    # This is an example that automatically calculate signing_key and key_scope
    location /s3_beijing_3 {
      proxy_auth_aws on;
      proxy_auth_aws_access_key your_aws_access_key; # Example AKIDEXAMPLE
      proxy_auth_aws_secret_key your_aws_secret_key; # Example LTAxxxxxxxx
      proxy_auth_aws_region cn-north-1;
      proxy_auth_aws_endpoint s3.cn-north-1.amazonaws.com.cn;
      proxy_auth_aws_bucket your_s3_bucket;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com;
    }
  }
```

## Security considerations
The V4 protocol does not need access to the actual secret keys that one obtains
from the IAM service. The correct way to use the IAM key is to actually generate
a scoped signing key and use this signing key to access S3. This nginx module
requires the signing key and not the actual secret key. It is an insecure practise
to let the secret key reside on your nginx server.

Note that signing keys have a validity of just one week. Hence, they need to
be refreshed constantly. Please useyour favourite configuration management
system such as saltstack, puppet, chef, etc. etc. to distribute the signing
keys to your nginx clusters. Do not forget to HUP the server after placing the new
signing key as nginx reads the configuration only at startup time.

A standalone python script has been provided to generate the signing key
```
./generate_signing_key -h
usage: generate_signing_key [-h] -k SECRET_KEY -r REGION [-s SERVICE]
                            [-d DATE] [--no-base64] [-v]

Generate AWS S3 signing key in it's base64 encoded form

optional arguments:
  -h, --help            show this help message and exit
  -k SECRET_KEY, --secret-key SECRET_KEY
                        The secret key generated using AWS IAM. Do not confuse
                        this with the access key id
  -r REGION, --region REGION
                        The AWS region where this key would be used. Example:
                        us-east-1
  -s SERVICE, --service SERVICE
                        The AWS service for which this key would be used.
                        Example: s3
  -d DATE, --date DATE  The date on which this key is generated in yyyymmdd
                        format
  --no-base64           Disable output as a base64 encoded string. This NOT
                        recommended
  -v, --verbose         Produce verbose output on stderr


./generate_signing_key -k wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY -r us-east-1
L4vRLWAO92X5L3Sqk5QydUSdB0nC9+1wfqLMOKLbRp4=
20160902/us-east-1/s3/aws4_request

```
## Supported environments
This plugin is tested against a variety of nginx versions, compilers, OS versions and hardware architectures. Take a look at the .travis.yml file or the latest travis build status to see the versions that the plugin has been tested against


## Known limitations
The 2.x version of the module currently only has support for GET and HEAD calls. This is because
signing request body is complex and has not yet been implemented.



## Credits
Original idea based on http://nginx.org/pipermail/nginx/2010-February/018583.html and suggestion of moving to variables rather than patching the proxy module.

Subsequent contributions can be found in the commit logs of the project.
