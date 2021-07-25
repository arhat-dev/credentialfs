# `bitwarden`

[Bitwarden](https://bitwarden.com/) password manager

## Supported Targets (`from`)

- [x] Login (`username` & `password`)
- [x] Custom Fields
- [x] Attachments

__NOTE:__ This app will not handle name collisions, please make sure the listed targets are unique in your vault, or you probably won't get correct data and updates.

## Config

```yaml
# your bitwarden service url
#
# to use official service at bitwarden.com, leave it empty
# or set it to `https://vault.bitwarden.com`
endpointURL: https://bw.internal

# save your username and password to system keychain
saveLogin: false

# 2FA method name, currently no supported
twoFactorMethod: ""

# Custom DeviceID, if not set, this app will set it with machine id
# if it could not find a suitable machine id, you have to provide
# a uuid here
deviceID: ""
```
