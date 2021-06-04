# CredentialFS

[![CI](https://github.com/arhat-dev/credentialfs/workflows/CI/badge.svg)](https://github.com/arhat-dev/credentialfs/actions?query=workflow%3ACI)
[![Build](https://github.com/arhat-dev/credentialfs/workflows/Build/badge.svg)](https://github.com/arhat-dev/credentialfs/actions?query=workflow%3ABuild)
[![PkgGoDev](https://pkg.go.dev/badge/arhat.dev/credentialfs)](https://pkg.go.dev/arhat.dev/credentialfs)
[![GoReportCard](https://goreportcard.com/badge/arhat.dev/credentialfs)](https://goreportcard.com/report/arhat.dev/credentialfs)
[![codecov](https://codecov.io/gh/arhat-dev/credentialfs/branch/master/graph/badge.svg)](https://codecov.io/gh/arhat-dev/credentialfs)

Userspace filesystem daemon for credentials stored in password managers

## Why this project?

Say you are using password manager (abbrv. `pm`) for your own credential management, but you always have to store some of the credentials locally for apps without the support for reading from system keychain, that can be risky once you have your computer hacked and the hacker can read these local credentials without your permit.

One solution is to develop a plugin or a wrapper script for these apps to read from system keychain, so you can store these credentials locally and safely.

Another solution is to mount a custom filesystem, which integrates with your password manager, and doesn't store credentials to local disk, everytime there is a file read request to your credential file, the filesystem daemon will request authorization via system security api from user to allow or deny the  read request. To protect these credentials from being overriden, you can pre-configure whether the filesystem is mounted read-only. And to update these credentials, you can use compaion command line tools to commit updates to a file

## Suitable Use Cases

- Sync credential files among your working computers with online password manager
- Store credentials directly in config files (e.g. kubeconfig using client certificate for authentication)
  - Then you can manage your home directory in a git system safely
- Store passwords in files (e.g. ssh password)
  - Then you can `cat /path/to/password` in your scripts, and run your scripts with authorization process

## Support Matrix

- OS
  - [x] `macos` (requires [`osxfuse`](https://github.com/osxfuse/osxfuse))
  - [ ] `windows`
  - [ ] `linux`
- Password Managers
  - [x] [`bitwarden`](./docs/pm/bitwarden.md)

## Config

Create a yaml config file like this:

```yaml
app:
  log:
  - level: verbose
    file: stderr

fs:
  # global mountpoint, all your credentials will be mounted to this
  # directory, you can find all files listed in `fs.spec[*].mounts.from`
  # in this directory, however their names are hex encoded string of
  # sha256 hash of `fs.spec[*].mounts.to`
  mountpoint: ${HOME}/.credentials
  # show fuse debug log output
  debug: false
  # filesystem spec
  # list of password managers and their file mounts
  spec:
  - pm:
      # (required) unique name (among all local credentialfs config) of this password manager config
      name: my-bitwarden-pm
      # (required) driver currently only supports `bitwarden`
      driver: bitwarden
      # please read ./docs/pm/{driver}.md for config reference
      config: {}
    # mount credentials as files from the password manager above
    #
    # NOTE: The mount operation here actually creates symlinks for your
    #       `mounts[*].to` since we haven't found a reasonabley easy way 
    #       to support file bind mount on all platforms, please let us
    #       know by creating a new issue if you have a good idea.
    mounts:
    - from: <Item Name>/<Item Key>
      # local mount path
      to: ${HOME}/.ssh/joe.doyle
      # how long will a successful authorization valid for
      # defaults to 0, which means always request authorization
      #
      # NOTE: the authorization is process specific, if you use
      #       different tools to read from a same credential file
      #       thir permit durations are timed individually
      permitDuration: 5s
```

## Build

Run `make credentialfs` in the project root, you can find built executable at `./build/credentialfs`

## Run

```bash
/path/to/credentialfs -c /path/to/your/config
```

## Acknowledgement

- [kbfs from keybase/client](https://github.com/keybase/client/blob/master/go/kbfs)
- [keybase/go-keychain](https://github.com/keybase/go-keychain)
- [github/certstore](https://github.com/github/certstore)

## LICENSE

```text
Copyright 2020 The arhat.dev Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
