---
title: "Seafile"
description: "Integrating Seafile with the Authelia OpenID Connect 1.0 Provider."
lead: ""
date: 2023-10-18T15:16:47+02:00
draft: false
images: []
menu:
  integration:
    parent: "openid-connect"
weight: 620
toc: true
community: true
---

## Tested Versions

* [Authelia]
  * [v4.38.0](https://github.com/authelia/authelia/releases/tag/v4.38.0)

* [Seafile] Server
  * [10.0.1](https://manual.seafile.com/changelog/server-changelog/#1001-2023-04-11)

## Before You Begin

{{% oidc-common %}}

### Assumptions

This example makes the following assumptions:

* __Application Root URL:__ `https://seafile.example.com`
* __Authelia Root URL:__ `https://auth.example.com`
* __Client ID:__ `seafile`
* __Client Secret:__ `insecure_secret`

## Configuration

### Authelia

The following YAML configuration is an example __Authelia__
[client configuration](../../../configuration/identity-providers/openid-connect/clients.md) for use with [Seafile]
which will operate with the above example:

```yaml
identity_providers:
  oidc:
    ## The other portions of the mandatory OpenID Connect 1.0 configuration go here.
    ## See: https://www.authelia.com/c/oidc
    clients:
    - id: 'seafile'
      description: 'Seafile'
      secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
      public: false
      authorization_policy: 'two_factor'
      redirect_uris:
        - 'https://seafile.example.com/oauth/callback/'
      scopes:
        - 'openid'
        - 'profile'
        - 'email'
      userinfo_signed_response_alg: 'none'
      token_endpoint_auth_method: 'client_secret_basic'
```

If you plan to also use [Seafile's WebDAV extension], which apparently [does not support OAuth bearer](https://github.com/haiwen/seafdav/issues/76), and the [desktop app](https://github.com/authelia/authelia/issues/2840), some access-control rules might be required:

```yaml
access_control:
  rules:
    - domain: 'seafile.example.com'
      resources:
        - '^/(api2?|seafhttp|media|seafdav)([/?].*)?$'
      policy: bypass
```

### Application

Configure [Seafile] to use Authelia as an [OpenID Connect 1.0] Provider.

1. [Seafile] may require some dependencies such as `requests_oauthlib` to be
   manually installed.  See the [Seafile] documentation in the [see
   also](#see-also) section for more information.

2. Edit your [Seafile] `seahub_settings.py` configuration file and add the
   following:

```python
ENABLE_OAUTH = True
OAUTH_ENABLE_INSECURE_TRANSPORT = False
OAUTH_CLIENT_ID = "seafile"
OAUTH_CLIENT_SECRET = "insecure_secret"
OAUTH_REDIRECT_URL = 'https://seafile.example.com/oauth/callback/'
OAUTH_PROVIDER_DOMAIN = 'auth.example.com'
OAUTH_AUTHORIZATION_URL = 'https://auth.example.com/api/oidc/authorization'
OAUTH_TOKEN_URL = 'https://auth.example.com/api/oidc/token'
OAUTH_USER_INFO_URL = 'https://auth.example.com/api/oidc/userinfo'
OAUTH_SCOPE = [
    "openid",
    "profile",
    "email",
]
OAUTH_ATTRIBUTE_MAP = {
    "email": (True, "email"),
    "name": (False, "name"),
    "id": (False, "not used"),
}

# Optional
#ENABLE_WEBDAV_SECRET = True
```

Optionally, [enable webdav
secrets](https://manual.seafile.com/config/seahub_settings_py/#user-management-options)
so that clients that do not support Oauth (e.g.,
[davfs2](https://savannah.nongnu.org/bugs/?57589)) can login via basic
auth.

## See Also

* [Seafile OAuth Authentication Documentation](https://manual.seafile.com/deploy/oauth/)
* [Seafile's WebDAV extension](https://manual.seafile.com/extension/webdav/)

[Authelia]: https://www.authelia.com
[Seafile]: https://www.seafile.com/
[Seafile's WebDAV extension]: https://manual.seafile.com/extension/webdav/
[OpenID Connect 1.0]: ../../openid-connect/introduction.md
