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
	"arhat.dev/credentialfs/pkg/manager"
	"arhat.dev/credentialfs/pkg/security"
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
	flags.AddFlagSet(log.FlagsForLogConfig("log.", cliLogConfig))
	flags.AddFlagSet(conf.FlagsForAppConfig("", &config.App))
	flags.AddFlagSet(conf.FlagsForFilesystemConfig("", &config.FS))

	return rootCmd
}

func run(appCtx context.Context, config *conf.Config) error {
	logger := log.Log.WithName("app")

	authHandler, err := security.NewAuthorizationHandler(config.App.AuthService.Name, config.App.AuthService.Config)
	if err != nil {
		return fmt.Errorf("failed to create authorization handler: %w", err)
	}

	keychainHandler, err := security.NewKeychainHandler(
		config.App.KeychainService.Name, config.App.KeychainService.Config,
	)
	if err != nil {
		return fmt.Errorf("failed to create keychain handler: %w", err)
	}

	mgr, err := manager.NewManager(appCtx, logger.WithName("mgr"), authHandler, keychainHandler, &config.FS)
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
			logger.E("manager stopped with error", log.Error(err2))
		}
	}()

	<-appCtx.Done()

	return nil
}
