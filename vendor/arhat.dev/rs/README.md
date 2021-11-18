# rs

[![CI](https://github.com/arhat-dev/rs/workflows/CI/badge.svg)](https://github.com/arhat-dev/rs/actions?query=workflow%3ACI)
[![PkgGoDev](https://pkg.go.dev/badge/arhat.dev/rs)](https://pkg.go.dev/arhat.dev/rs)
[![GoReportCard](https://goreportcard.com/badge/arhat.dev/rs)](https://goreportcard.com/report/arhat.dev/rs)
[![Coverage](https://badge.arhat.dev/sonar/coverage/arhat-dev_rs?branch=master&token=563ff8cf318c9303285b4dd4eeb0c660)](https://sonar.arhat.dev/dashboard?id=arhat-dev_rs)
[![Telegram](https://img.shields.io/static/v1?label=telegram&message=join&style=flat-square&logo=telegram&logoColor=ffffff&color=54A7E6&labelColor=555555)](https://t.me/joinchat/xcTR4nLDTOs2Yzcy)

`R`endering `S`uffix Support for yaml

## What?

Before we start, let's agree on the concept `renderer` is just a simple function that takes some input to generate some output.

```text
input -> [ renderer ] -> output
```

Now, let's start from an ordinary yaml doc:

```yaml
foo: bar
```

Everything's static, once unmarshaled, `foo` gets value `bar`.

Now what if we would like to use some environment variable value as `foo`'s value in unix shell style?

```yaml
foo: ${FOO}
```

You can only get `${FOO}` for your `foo` after unmarshaling, you have to code you own logic to map `${FOO}` to some system environment variable.

WAIT A MINUTE! Isn't it actually a `renderer` with its usage specific to `foo`?

Rendering suffix is here to help to reuse your renderers, it offers a way to make your yaml doc dynamic on its own, you control config resolving in yaml, not in compiled code.

### How it looks?

Let's continue with the environment variable support, say we have developed a renderer `env` (which calls `os.ExpandEnv` to map env reference to its value):

```yaml
foo@env: ${FOO}
```

Probably you have already figured out what's going on there before I would explain:

`@` is like a notifier, and notifies the renderer `env` with value `${FOO}`, then `env` does its own job and generates some output using `os.ExpandEnv`, and at last, the output is set as `foo`'s value.

It's simple and straightforward, right?

As you may also be wondering how can `foo@env` be resolved as `foo` since they are completely different field name! That's what we are taking care of, see [How it works?](#how-it-works) section for brief introduction.

## Prerequisites

- Use `gopkg.in/yaml.v3` for yaml marshaling/unmarshaling

## Features

- Field specific rendering: customizable in-place yaml data rendering
  - Add a suffix starts with `@`, followed by some renderer name, to your yaml field name as rendering suffix (e.g. `foo@<renderer-name>: bar`)
- Type hinting: keep you data as what it supposed to be
  - Add a type hint suffix `?<some-type>` to your renderer (e.g. `foo@<renderer-name>?[]obj: bar` suggests `foo` should be an array of objects using result from `<renderer-name>` generated with input `bar`)
  - See [list of supported type hints](https://github.com/arhat-dev/rs/blob/v0.5.1/typehint.go#L209)
- Data merging and patching made esay: create patching spec in yaml doc
  - Add a patching suffix `!` to your renderer (after the type hint if any), feed it a [patch spec](https://pkg.go.dev/arhat.dev/rs#PatchSpec) object
  - Built-in `jq` (as `select` field) and rfc6902 json-patch (as `patch[*]`) support to select partial data from the incoming data.
- Renderer chaining: render you data with a rendering pipeline
  - Concatenate you renderers with pipes (`|`), get your data rendered through the pipeline (e.g. join three renderers `a`, `b`, `c` -> `a|b|c`)
- Supports arbitraty yaml doc without type definition in your own code.
  - Use [`AnyObject`](https://pkg.go.dev/arhat.dev/rs#AnyObject) as `interface{}`.
  - Use [`AnyObjectMap`](https://pkg.go.dev/arhat.dev/rs#AnyObjectMap) as `map[string]interface{}`.
- Everything (except `map`s using `interface{}` key) `gopkg.in/yaml.v3` supports are supported.
- Extended but still vanilla yaml, your yaml doc stays valid for all standard yaml parser.

Sample YAML doc with all features mentioned above:

```yaml
# patch spec `!`
foo@a!: &foo
  # rendering pipeline with type hint
  value@env|http?[]obj: https://example.com/${FOO_FILE_PATH}
  merge:
  - value@file: ./value-a.yml
    select: |-
      [ .[] | sort ]
  patch:
  - { op: remove, path: /0/foo }
  - op: add
    path: /0/foo
    value: "bar"
    select: '. + "-suffix-from-jq-query"'
  select: |-
    { foo: .[0].foo, bar: .[1].bar }

bar@a!: *foo
```

__NOTE:__ This module provides no renderer implementation, and the only built-in renderer is a pseudo renderer with empty name that skips rendering (output is what input is) for data patching and type hinting purpose (e.g. `foo@?int!: { ... patch spec ... }`). You have to roll out your own renderers. If you are in a hurry and want some handy renderers, try our [arhat.dev/pkg/rshelper.DefaultRenderingManager](https://pkg.go.dev/arhat.dev/pkg/rshelper#DefaultRenderingManager), it will give you `env`, `template` and `file` renderers.

__NOTE:__ This library also supports custom yaml tag `!rs:<renderer>` (local tag) and `!tag:arhat.dev/rs:<renderer>` (global tag) with the same feature set as `@<renderer>` to your fields, but we do not recommend using that syntax as it may have issues with some yaml parser, a close example (since yaml anchor and alias cannot be used with yaml tag at the same time) of the one above is:

```yaml
# not supported
# foo: !rs:a! &foo
foo: !tag:arhat.dev/rs:a!
  value: !rs:env|http?[]obj https://example.com/${FOO_FILE_PATH}
  merge:
  - value: !rs:file ./value-a.yml
    select: |-
      [ .[] | sort ]
  patch:
  - { op: remove, path: /0/foo }
  - op: add
    path: /0/foo
    value: "bar"
    select: '. + "-suffix-from-jq-query"'
  select: |-
    { foo: .[0].foo, bar: .[1].bar }

# not supported
# bar: !rs:a! *foo
```

## Usage

See [example_test.go](./example_test.go)

__NOTE:__ You can find more examples in [`arhat-dev/dukkha`][dukkha]

## Known Limitations

See [known_limitation_test.go](./known_limitation_test.go) for sample code and workaround.

- Golang built-in map with rendering suffix applied to map key are treated as is, rendering suffix won't be recognized.
  - For `map[string]interface{}`, `foo@foo: bar` is just a map item with key `foo@foo`, value `bar`, no data to be resolved.
  - The reason for this limitation is obvious since built-in map types don't have `BaseField` embedded, but it can be counterintuitive when you have a map field in a struct having `BaseField` embedded.

## How it works?

IoC (Inversion of Control) is famous for its application in DI (Dependency Injection), but what it literally says is to control the outside world at somewhere inside the world, that's the start point.

Custom yaml unmarshaling requires custom implementation of `yaml.Unmarshaler`, so usually you just get your structs unmarshaled by `yaml.Unmarshal` directly.

We implemented something called `BaseField`, it lives in your struct as a embedded field, all its methods are exposed to the outside world by default, and guess what, it implements `yaml.Unmarshaler`, so your struct implements `yaml.Unmarshaler` as well.

But can you control sibling fields in a struct? Not possible in golang unless with the help of outside world, that's why we need `Init()` function, calling `Init()` with your struct actually activates the `BaseField` in it, `Init()` function tells the inner `BaseField` what fields the parent struct have (its sibling fields), with the help of reflection.

You only have to call `Init()` once for the top level struct, since then the `BaseField` in it knows what to do with its sibling fields, it will also search for all structs with `BaseField` embedded when unmarshaling, call `Init()` for them, until the whole yaml doc is unmarshaled.

During the unmarshaling process, `BaseField.UnmarshalYAML` get called by `yaml.Unmarhsal`, it checks the input yaml field names, if a yaml field name has a suffix starting with `@`, then that yaml field will be treated as using rendering suffix, `BaseField` parses the yaml field name to know the real field name is (e.g. `foo@bar`'s real field name is `foo`) and sets the rendering pipeline with the suffix, it also saves the yaml field value on its own but not setting the actual strcut field, when you call `my_struct_with_BaseField.ResolveFields()`, it feeds the rendering pipeline with saved field value to generate actual field value and set that as struct field value.

All in all, `BaseField` handles everything related to yaml unmarshaling to support rendering suffix after initial activation, so all you need to do is to embed a `BaseField` as the very first field in your struct where you want to support rendering suffix and activate the top level struct (with `BaseField` embedded, which can be some inner field) with a `Init()` function call.

## FAQ

Have a look at [FAQ.md](./FAQ.md) or start/join a [discussion on github](https://github.com/arhat-dev/rs/discussions).

## A bit of history

This project originates from [`dukkha`][dukkha] in July 2021.

At that time, I was looking for some task runner with matrix support to ease my life with my [multi-arch oci image build pipelines](https://github.com/arhat-dev/dockerfile) and all repositories in this organization, hoping I can finally forget all these repeated work on repo maintenance.

After some time, [`dukkha`][dukkha] fulfilled nearly all my expectations with buildah, golang and cosign support, and I made the original package `arhat.dev/dukkha/pkg/field` standalone as this project to promote the idea.

Please feel free to share your thoughts about it at github discussion, feedbacks are always welcome, and also email me if you would like to join my tiny idea sharing group.

## LICENSE

```txt
Copyright 2021 The arhat.dev Authors.

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

[dukkha]: https://github.com/arhat-dev/dukkha
