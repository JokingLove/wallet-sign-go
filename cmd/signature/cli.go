package main

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/log"

	"github.com/urfave/cli/v2"

	"github.com/JokingLove/wallet-sign-go/common/cliapp"
	"github.com/JokingLove/wallet-sign-go/config"
	flags2 "github.com/JokingLove/wallet-sign-go/flags"
	"github.com/JokingLove/wallet-sign-go/leveldb"
	"github.com/JokingLove/wallet-sign-go/services/rpc"
)

func runRpc(ctx *cli.Context, shutdown context.CancelCauseFunc) (cliapp.Lifecycle, error) {
	fmt.Println("running grpc services...")
	cfg := config.NewConfig(ctx)
	grpcServerCfg := &rpc.RpcServerConfig{
		GrpcHostname: cfg.RpcServer.Host,
		GrpcPort:     cfg.RpcServer.Port,
		KeyName:      cfg.KeyName,
		KeyPath:      cfg.CredentialsFile,
		HsmEnable:    cfg.HsmEnable,
	}
	db, err := leveldb.NewKeyStore(cfg.LevelDbPath)
	if err != nil {
		log.Error("new key store level db", "err", err)
	}
	return rpc.NewRpcServer(db, grpcServerCfg)
}

func NewCli(GitCommit string, GitData string) *cli.App {
	flags := flags2.Flags
	return &cli.App{
		// Version:              params.VersionWithCommit(GitCommit, GitData),
		Version:              fmt.Sprintf("%s-%s", GitCommit, GitData),
		Description:          "An exchange wallet scanner services with rpc and rest api services",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:        "rpc",
				Flags:       flags,
				Description: "Run rpc services",
				Action:      cliapp.LifecycleCmd(runRpc),
			},
			{
				Name:        "version",
				Description: "Show project version",
				Action: func(ctx *cli.Context) error {
					cli.ShowVersion(ctx)
					return nil
				},
			},
		},
	}
}
