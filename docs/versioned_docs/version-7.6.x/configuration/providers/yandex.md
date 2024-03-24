---
id: yandex
title: Yandex
---

1. [Add a new OAuth consumer](https://yandex.ru/dev/id/doc/en/how-to)
    * In "Callback URL" use `https://<oauth2-proxy>/oauth2/callback`, substituting `<oauth2-proxy>` with the actual 
      hostname that oauth2-proxy is running on.
    * In Permissions section select:
        * Access to email address
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=yandex
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```
