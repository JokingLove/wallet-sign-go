package rpc

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/JokingLove/wallet-sign-go/hsm"
	"github.com/JokingLove/wallet-sign-go/leveldb"
	"github.com/JokingLove/wallet-sign-go/protobuf/wallet"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const MaxReceiveMessageSize = 1024 * 1024 * 30000

type RpcServerConfig struct {
	GrpcHostname string
	GrpcPort     int
	KeyPath      string
	KeyName      string
	HsmEnable    bool
}

type RpcServer struct {
	*RpcServerConfig
	db        *leveldb.Keys
	HsmClient *hsm.HsmClient

	wallet.UnimplementedWalletServiceServer
	stopped atomic.Bool
}

func (s *RpcServer) Stop(ctx context.Context) error {
	s.stopped.Store(true)
	return nil
}

func (s *RpcServer) Stopped() bool {
	return s.stopped.Load()
}

func NewRpcServer(db *leveldb.Keys, config *RpcServerConfig) (*RpcServer, error) {
	hsmClient, err := hsm.NewHSMClient(context.Background(), config.KeyPath, config.KeyName)
	if err != nil {
		log.Error("new hsm client fail", "err", err)
		// return nil, err
	}

	return &RpcServer{
		RpcServerConfig: config,
		db:              db,
		HsmClient:       hsmClient,
	}, nil
}

func (s *RpcServer) Start(ctx context.Context) error {
	go func(s *RpcServer) {
		addr := fmt.Sprintf("%s: %d", s.GrpcHostname, s.GrpcPort)
		log.Info("start rpc services", "addr", addr)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Error("Could not start tcp listener.")
		}

		opt := grpc.MaxRecvMsgSize(MaxReceiveMessageSize)

		gs := grpc.NewServer(
			opt,
			grpc.ChainStreamInterceptor(nil),
		)

		reflection.Register(gs)

		wallet.RegisterWalletServiceServer(gs, s)

		log.Info("Grpc info ", "port", s.GrpcPort, "address", listener.Addr())
		if err := gs.Serve(listener); err != nil {
			log.Error("Could not GRPC services")
		}
	}(s)
	return nil
}
