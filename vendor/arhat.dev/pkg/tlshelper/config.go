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

package tlshelper

import (
	"arhat.dev/rs"
)

type TLSPreSharedKeyConfig struct {
	rs.BaseField `json:"-" yaml:"-"`

	// map server hint(s) to pre shared key(s)
	// colon separated base64 encoded key value pairs
	ServerHintMapping []string `json:"server_hint_mapping" yaml:"server_hint_mapping"`
	// the client hint provided to server, base64 encoded value
	IdentityHint string `json:"identity_hint" yaml:"identity_hint"`
}

// TLSConfig for common tls settings, support both client and server tls
// nolint:maligned
type TLSConfig struct {
	rs.BaseField `json:"-" yaml:"-"`

	Enabled bool `json:"enabled" yaml:"enabled"`

	CaCert string `json:"ca_cert" yaml:"ca_cert"`
	Cert   string `json:"cert" yaml:"cert"`
	Key    string `json:"key" yaml:"key"`

	ServerName         string `json:"server_name" yaml:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	// write tls session shared key to this file
	KeyLogFile   string   `json:"key_log_file" yaml:"key_log_file"`
	CipherSuites []string `json:"cipher_suites" yaml:"cipher_suites"`

	// options for dtls
	AllowInsecureHashes bool `json:"allow_insecure_hashes" yaml:"allow_insecure_hashes"`

	PreSharedKey TLSPreSharedKeyConfig `json:"pre_shared_key" yaml:"pre_shared_key"`
}
