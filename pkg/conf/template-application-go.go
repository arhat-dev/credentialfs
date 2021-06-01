/*
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
*/

package conf

import (
	"arhat.dev/pkg/log"
	"github.com/spf13/pflag"
)

type Config struct {
	App AppConfig `json:"app" yaml:"app"`
}

type AppConfig struct {
	Log log.ConfigSet `json:"log" yaml:"log"`

	Foo string `json:"foo" yaml:"foo"`
}

func FlagsForAppConfig(prefix string, config *AppConfig) *pflag.FlagSet {
	fs := pflag.NewFlagSet("app", pflag.ExitOnError)

	fs.StringVar(&config.Foo, prefix+"foo", "bar", "set value of foo")

	return fs
}
