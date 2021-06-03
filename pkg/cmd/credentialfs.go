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

package cmd

import (
	"context"
	"fmt"

	"arhat.dev/pkg/log"
	"github.com/spf13/cobra"

	"arhat.dev/credentialfs/pkg/conf"
	"arhat.dev/credentialfs/pkg/constant"
	"arhat.dev/credentialfs/pkg/fs"

	// password managers
	_ "arhat.dev/credentialfs/pkg/pm/bitwarden"
)

func NewRootCmd() *cobra.Command {
	var (
		appCtx       context.Context
		configFile   string
		config       = new(conf.Config)
		cliLogConfig = new(log.Config)
	)

	rootCmd := &cobra.Command{
		Use:           "credentialfs",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Use == "version" {
				return nil
			}

			var err error
			appCtx, err = conf.ReadConfig(cmd, &configFile, cliLogConfig, config)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(appCtx, config)
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringVarP(&configFile, "config", "c", constant.DefaultConfigFile,
		"path to the config file")
	flags.AddFlagSet(conf.FlagsForAppConfig("", &config.App))

	return rootCmd
}

func run(appCtx context.Context, config *conf.Config) error {
	logger := log.Log.WithName("app")

	_ = logger
	mgr, err := fs.NewManager(appCtx, config.FS)
	if err != nil {
		return fmt.Errorf("failed to create fs manager: %w", err)
	}

	err = mgr.Start()
	if err != nil {
		return fmt.Errorf("failed to start fs manager: %w", err)
	}

	defer func() {
		err2 := mgr.Stop()
		if err2 != nil {
			fmt.Println(err2.Error())
		}
	}()

	<-appCtx.Done()

	return nil
}
