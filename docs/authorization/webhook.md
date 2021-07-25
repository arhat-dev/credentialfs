# `webhook`

## Config

```yaml
name: webhook
config:
  headers:
  - name: Authroization
    value: Basic username:password
  tls:
    enabled: true
    certData: <base64-encoded-tls-cert>
    keyData: <base64-encoded-tls-key>
```
