# pip install fails with CERTIFICATE_VERIFY_FAILED on macOS

Fresh Python 3.12 from python.org on macOS 14.5, pip 24.0.

```
$ pip install requests
ERROR: Could not install packages due to an OSError: HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded with url: /simple/requests/ (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
```

## Cause

The python.org installer ships its own OpenSSL and does not use the system keychain; the certifi bundle is only installed by a post-install script.

## Fix

- Run the bundled script: `open "/Applications/Python 3.12/Install Certificates.command"`
- Re-run `pip install requests`
- If it still fails, `pip install --upgrade certifi`

## Tags

python, pip, tls, macos
