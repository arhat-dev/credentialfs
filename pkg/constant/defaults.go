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

package constant

import (
	"os"
	"path/filepath"
	"runtime"
)

// nolint:revive
var (
	DefaultConfigFile = ""
)

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil || len(homeDir) == 0 {
		switch runtime.GOOS {
		case "windows":
			DefaultConfigFile = ""
		default:
			DefaultConfigFile = "/etc/credentialfs/config.yaml"
		}
	} else {
		DefaultConfigFile = filepath.Join(homeDir, ".config", "credentialfs", "config.yaml")
	}
}
