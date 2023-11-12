# Securing API with Envoy and XSUAA in BTP Cloud Foundry

An example of protecting API endpoints with Envoy Proxy sidecar and XSUAA in BTP Cloud Foundry.


## Introduction


Have you ever stumbled upon the fact that every application in BTP Cloud Foundry is accessed through
HTTPS port 443 but the application itself doesn't need to handle HTTPS and deals with just
HTTP on port 8080?

The answer is [Envoy Proxy](https://www.envoyproxy.io/).  Envoy is a powerful network proxy with
a pluggable filter chain mechanism, HTTP/2 and gRPC support, advanced load balancing, observability,
and more.  It is the backbone of Istio service mesh and Cloud Foundry's networking.

In this example, we will use the power of Envoy to secure our test application
[httpbin](https://github.com/postmanlabs/httpbin) deployed to BTP Cloud Foundry.
Envoy Sidecar will validate Jwt XSUAA tokens and control access to the upstream application.

![architecture](https://github.com/sappier/example-cf-envoy-xsuaa/assets/36699371/1b96881c-008b-4660-8637-0887298db6a7)


## Prepare application configuration

All files are available on Github: https://github.com/sappier/example-cf-envoy-xsuaa.

```
$ git clone https://github.com/sappier/example-cf-envoy-xsuaa.git
$ cd example-cf-envoy-xsuaa
```

### Envoy configuration

There are many excellent resources about Envoy configuration.
The [References](#References) section contains a few links with more information.

To make the whole deployment easier, we use the [Ruby ERB](https://docs.ruby-lang.org/en/master/ERB.html)
template to specify an envoy configuration.  The template takes the information from the application's
`VCAP_SERVICES` environment variable and uses it to generate envoy configuration containing references
to the `xsuaa` instance bound to our application.

The template is stored in the `envoy.yaml.erb` file.  And we highlight here the most important parts.

Extract XSUAA information from the application's binding:

```yaml
<% require 'uri' -%>
<% XSUAA = URI.parse(VCAP_SERVICES["xsuaa"][0]["credentials"]["url"]) -%>
```

A listener to receive all incoming requests on port 8080:

```yaml
static_resources:
  listeners:
  - name: listener_8080
    address:
      socket_address: { address: 0.0.0.0, port_value: 8080 }
```

A `Jwt Authentication` filter configuration.  Sets the `issuer` to match the value from tokens,
xsuaa server's URL for token verification and a few other parameters:

```yaml
          - name: envoy.filters.http.jwt_authn
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
              providers:
                xsuaa:
                  issuer: <%= URI.join(XSUAA.to_s, "/oauth/token") %>
                  forward: true
                  remote_jwks:
                    http_uri:
                      uri: <%= URI.join(XSUAA.to_s, "/token_keys") %>
                      cluster: xsuaa
                      timeout: 5s
                    cache_duration: { seconds: 600 }
```

Routes rules specify which endpoints to protect and which to keep open.
The path `/robots.txt` doesn't have the `requires` section, hence Jwt verification is turned off for it.
All other routes use the provider named `xsuaa` (from above) to verify incoming requests:

```yaml
              rules:
              - match:
                  prefix: /robots.txt
              - match:
                  prefix: /
                requires: { provider_name: xsuaa }
```

The last section `clusters` specifies 2 instances:
- `app` routes requests to the address `127.0.0.1:8000` where our `httpbin` application listens.
- `xsuaa` with the xsuaa server address and TLS config to connect to xsuaa over HTTPS.

### Manifest file

A relevant part of the `manifest.yml` is:

```yaml
  buildpacks:
    - https://github.com/r0mk1/cf-envoyproxy-buildpack.git
    - python_buildpack
  command: gunicorn -b 127.0.0.1:8000 -k gevent httpbin:app
  services:
    - xsuaa
  health-check-type: http
  health-check-http-endpoint: /robots.txt
```

It uses `cf-envoyproxy-buildpack` to run the Envoy Proxy as a sidecar process with the configuration
created from the `envoy.yaml.erb` template.

The `python_buildpack` installs the `httpbin` web application with dependencies specified
in the `requests.txt` file.  The application runs through the `gunicorn` http server on port 8000.

The `services` section binds the service instance named `xsuaa` to our application.

And finally, it tells Cloud Foundry to use our unprotected endpoint for health checks.


## Deploy the application

First, we need to create an instance of the xsuaa service with the name `xsuaa`, the same as in the manifest.

```
$ cf create-service xsuaa application xsuaa
Creating service instance xsuaa in ...

Service instance xsuaa created.
OK
```

Afterwards, we can deploy the application:

```
$ cf push
Pushing app httpbin to ...
...
name:              httpbin
requested state:   started
routes:            httpbin.cfapps.us10.hana.ondemand.com
...
#0   running   2023-11-11T17:04:59Z   0.0%   0 of 0   0 of 0   0/s of 0/s
```

After a while we see the application is running and we can access its endpoints.
Let's check the unprotected one first:

```
$ curl https://httpbin.cfapps.us10.hana.ondemand.com/robots.txt
User-agent: *
Disallow: /deny
```

As we see our '/robots.txt' returns data without the need to provide an authentication token.

Now try a protected endpoint and see the response 401 Unauthorized:

```
$ curl https://httpbin.cfapps.us10.hana.ondemand.com/uuid
Jwt is missing
```

Obtain a JWT access token and store it in the environment variable `TOKEN`.
Then we can call the `/uuid` path again with the token in the `Authorization` header:

```
$ curl -H "Authorization: Bearer $TOKEN" https://httpbin.cfapps.us10.hana.ondemand.com/uuid
{"uuid":"f767a625-c98b-4e94-b113-Boise5ff4me0ad"}
```

Voilà!


## Bonus

There is an `admin` section at the beginning of the envoy configuration.  It allows to see
detailed statistics of (un)authorized requests:

```
$ cf ssh httpbin -c 'curl -s localhost:9909/stats?filter=http.ingress_http.jwt_authn'
http.ingress_http.jwt_authn.allowed: 9
http.ingress_http.jwt_authn.cors_preflight_bypassed: 0
http.ingress_http.jwt_authn.denied: 1
http.ingress_http.jwt_authn.jwks_fetch_failed: 0
http.ingress_http.jwt_authn.jwks_fetch_success: 1
http.ingress_http.jwt_authn.jwt_cache_hit: 0
http.ingress_http.jwt_authn.jwt_cache_miss: 1
```

Or even export statistics to Prometheus:

```
cf ssh httpbin -c 'curl -s localhost:9909/stats/prometheus'
```

Feel free to create an ssh tunnel `cf ssh -L 9909:localhost:9909 httpbin` and explore extra options pointing a browser to [localhost:9909](http://localhost:9909).

See more details at [Administration interface](https://www.envoyproxy.io/docs/envoy/latest/operations/admin).


## References:

1. [Get started with Envoy Proxy in 5 minutes](https://tetrate.io/blog/get-started-with-envoy-in-5-minutes/)
1. [Configuring JWT Authentication in Envoy Proxy](https://www.scottguymer.co.uk/post/configuring-jwt-authentication-in-envoy/)
1. [ERB – Ruby Templating](https://docs.ruby-lang.org/en/master/ERB.html)
1. [Envoy Proxy buildpack for Cloud Foundry](https://github.com/r0mk1/cf-envoyproxy-buildpack)
1. [Securing API with Envoy and XSUAA in BTP Cloud Foundry](https://github.com/sappier/example-cf-envoy-xsuaa)
