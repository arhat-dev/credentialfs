# Release Notes

## Features

- Add foo support #issue-ref
- Add bar support #issue-ref

## Bug fixes

- Fixed foo #issue-ref
- Fixed bar #issue-ref #pr-ref

## Breaking Changes

- Foo ...
- Bar ...

## Changes since `{{ .Env.CHANGELOG_SINCE }}`

{{ .Env.CHANGELOG }}

## Images

- `ghcr.io/arhat-dev/credentialfs:{{ .Env.GIT_TAG }}`

## Helm Charts

- Have a look at [ArtifactHub](https://artifacthub.io/packages/helm/arhatdev/credentialfs)
- Checkout chart [source code](https://github.com/arhat-dev/credentialfs/blob/{{ .Env.GIT_TAG }}/cicd/deploy/charts/credentialfs)
