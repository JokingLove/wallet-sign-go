package rpc

import (
	"context"
	"errors"

	"github.com/JokingLove/wallet-sign-go/leveldb"
	"github.com/JokingLove/wallet-sign-go/protobuf"
	"github.com/JokingLove/wallet-sign-go/protobuf/wallet"
	"github.com/JokingLove/wallet-sign-go/ssm"
	"github.com/ethereum/go-ethereum/log"
)

func (s *RpcServer) GetSupportSignWay(ctx context.Context, in *wallet.SupportSignWayRequest) (*wallet.SupportSignWayResponse, error) {
	resp := &wallet.SupportSignWayResponse{
		Code: wallet.ReturnCode_ERROR,
	}

	cryptoType, err := protobuf.ParseTransactionType(in.Type)
	if err != nil {
		resp.Msg = "input type error"
		return resp, nil
	}
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Msg = "support this sign way = " + string(cryptoType)
	resp.Support = true
	return resp, nil
}

func (s *RpcServer) ExportPublicKeyList(ctx context.Context, in *wallet.ExportPublicKeyRequest) (*wallet.ExportPublicKeyResponse, error) {
	resp := &wallet.ExportPublicKeyResponse{
		Code: wallet.ReturnCode_ERROR,
	}

	cryptoType, err := protobuf.ParseTransactionType(in.Type)
	if err != nil {
		resp.Msg = "input type error"
		return resp, err
	}

	if in.Number > 10000 {
		resp.Msg = "Number must be less than 10000"
		return resp, nil
	}

	var keyList []leveldb.Key
	var retKeyList []*wallet.PublicKey

	for counter := 0; counter <= int(in.Number); counter++ {
		var priKeyStr, pubKeyStr, compressPubkeyStr string
		var err error

		switch cryptoType {
		case protobuf.ECDSA:
			priKeyStr, pubKeyStr, compressPubkeyStr, err = ssm.CreateECDSAKeyPair()
		case protobuf.EDDSA:
			priKeyStr, pubKeyStr, err = ssm.CreateEdDSAKeyPair()
			compressPubkeyStr = pubKeyStr
		default:
			return nil, errors.New("unsupported key type")
		}
		if err != nil {
			log.Error("create key pair fail", "err", err)
			return nil, err
		}

		keyItem := leveldb.Key{
			PrivateKey: priKeyStr,
			PubKey:     pubKeyStr,
		}
		pubKeyItem := &wallet.PublicKey{
			CompressPubkey: compressPubkeyStr,
			Pubkey:         pubKeyStr,
		}

		retKeyList = append(retKeyList, pubKeyItem)
		keyList = append(keyList, keyItem)
	}

	isOk := s.db.StoreKeys(keyList)
	if !isOk {
		log.Error("store keys fail", "isOk", isOk)
		return nil, errors.New("store keys fail")
	}

	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Msg = "crete keys success"
	resp.PublicKey = retKeyList
	return resp, nil
}

func (s *RpcServer) SignTxMessage(ctx context.Context, in *wallet.SignTxMessageRequest) (*wallet.SignTxMessageResponse, error) {
	resp := &wallet.SignTxMessageResponse{
		Code: wallet.ReturnCode_ERROR,
	}
	cryptoType, err := protobuf.ParseTransactionType(in.Type)
	if err != nil {
		resp.Msg = "input type error"
		return resp, err
	}

	privKey, ok := s.db.GetPrivKey(in.PublicKey)
	if !ok {
		return nil, errors.New("get private key by public key fail")
	}

	var signature string
	var err2 error

	switch cryptoType {
	case protobuf.ECDSA:
		signature, err2 = ssm.SignECDSAMessage(privKey, in.MessageHash)
	case protobuf.EDDSA:
		signature, err2 = ssm.SignEdDSAMessage(privKey, in.MessageHash)
	default:
		return nil, errors.New("unsupported key type")
	}
	if err2 != nil {
		return nil, err2
	}

	resp.Msg = "sign tx message success"
	resp.Signature = signature
	resp.Code = wallet.ReturnCode_SUCCESS
	return resp, nil
}