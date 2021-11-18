# Frequently Asked Questions

## What Renderer Suffix is Not?

It's not a yaml extension, also not the reserved yaml keyword `@`

## What is a Rendering Suffix?

As indicated by the name, it's a suffix used for rendering.

More specifically, it is:

- A __name suffix__ in `@<renderer-name>` format
- Can be applied to any yaml field name
  - e.g. `foo@<renderer-name>: ...`
- Is used to set value generation engine (the renderer)
- But __DOES NOT CHANGE__ the field name.

Example:

Say you have a struct defined with `foo` field:

```go
type Example struct {
  Foo string `yaml:"foo"`
}
```

In usual case, only parsing yaml docs with exact `foo` key like

```yaml
foo: something something
```

to your `Example` stuct (using `yaml.Unmarshal()` from [go-yaml](https://github.com/go-yaml/yaml)) can set the value of `foo`, any changes to the field name will be treated as a different field.

But with rendering suffix support, yaml docs like `foo@my-renderer: woo` and `foo@another-renderer: cool` (change the text between `@` and `:`, you get your own examples) can also be parsed as the `Example` type with `foo` field set.

## Why making `@` as rendering suffix start?

`@` is rarely used in yaml field name in my personal experience.

## What Can Rendering Suffix Do?

To generate field value dynamically, aka. Conditional Rendering for any single yaml field.

## Why adding suffix to field names, not extending yaml or create a parser?

Build another yaml parser to support this feature is cool, but your yaml file will not be recognized by any other yaml parsers unless you implement such extension to other yaml parsers or this is standardized in yaml spec (which is not likely to happen for such dynamic content generation)

Hacking field names means yaml docs using renderering suffix feature can be parsed and validated with any existing yaml parsers, you can limit renderer usage in your own validator

Take golang for example, you can include rendering suffix in yaml field tag to make certain renderer mandatory

```go
// struct ValidateFoo is a struct without rendering suffix support
// it is used to validate exsiting yaml files using rendering suffix
type ValidateFoo struct {
  // limit bar to always use `http` renderer only
  Bar string `yaml:"bar@http"`
  // limit woo to not using any renderer
  Woo string `yaml:"woo"`
}
```

## Why? (How comes this idea?)

A piece of software configuration is like a contract between developer and end user: set this, do that.

For very long time, both writing and reading/resolving software configuration are tedious and error prone, especially when you want to achieve felixibility to some extent.

Let's discuss a simple scenario, take application config as this

```go
type Config struct {
    A string
    B int
    C float64

    // RemoteHostScript for remote host execution
    RemoteHostScript string `yaml:"remote_host_script"`
}
```

What whould you do when you want to support environment variables for its fields `A`, `B`, `C`, while not `remote_host_script` (obviously the `remote_host_script` should be executed in some remote system).

```yaml
a: ${ENV_FOR_A}
b: ${ENV_FOR_B}
c: ${ENV_FOR_C}

remote_host_script: |-
  #!/bin/sh

  echo ${ENV_WITH_DIFFERENT_CONTEXT}
```

- Solution 1: Make `remote_host_script` a file path reference (or add a new field like `remote_host_script_file`)
  - Simple and effective, but now you have two source of remote host script, more compiled code logic added, more document to come for preferred options when both is set. End user MUST read your documentation in detail for such subtle issues (if you are good at documenting).
- Solution 2: Expand environment variables before unmarshaling
  - What would you do with `${ENV_WITH_DIFFERENT_CONTEXT}`? Well, you can unmarshal the config into two config, one with environment variables expanded, another not, and merge them into one.
  - Looks like a effective solution, but now you have to do the merge in compiled code.
- Solution 3: Unmarshal yaml as `map[string]interface{}` first, then do custom handling for every field
  - Now you have to work with types manually, tedious yet error prone job starts now.
- Solution 4: Create a new DSL, add some keywords...
  - We have already seen so many DSLs created just for configuration purpose, almost none of them really simplified the configuration management, and usually only useful for development not deployment.

As developers, what we actually need is let end user decide which field is resolved by what method, and we just control when to resolve which fields.

Rendering suffix is applicable to every single yaml field, doing exactly what end user need, and it can resolve fields part by part with certain strategy in code, which is exactly what developers want.

Rendering suffix does one thing to make both end users and developers happy:

Make your configuration flexible while still intuitive.

With rendering suffix, developers don't define how, but only control when to resolve. Just provide end users some easy to understand renderers, do not confine their creativity and use case to certain resolving rules.

Now, think again, would gradle be a better tool using dynamic yaml instead of Groovy DSL? Could GitOps for kubernetes be more easier with rendering suffix yaml instead of special purpose built kustomize or helm?
