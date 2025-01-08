package hsm

import (
	"context"
	"encoding/hex"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/api/option"
)

type HsmClient struct {
	Ctx     context.Context
	KeyName string
	Gclient *kms.KeyManagementClient
}

func NewHSMClient(ctx context.Context, keyPath string, keyName string) (*HsmClient, error) {
	apikey := option.WithCredentialsFile(keyPath)

	client, err := kms.NewKeyManagementClient(ctx, apikey)
	if err != nil {
		log.Error("new key manager client fail", "err", err)
		return nil, err
	}
	return &HsmClient{Ctx: ctx, KeyName: keyName, Gclient: client}, nil
}

func (hsm *HsmClient) SignTransaction(hash string) (string, error) {
	hashByte, _ := hex.DecodeString(hash)
	req := kmspb.AsymmetricSignRequest{
		Name: hsm.KeyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: hashByte[:],
			},
		},
	}

	resp, err := hsm.Gclient.AsymmetricSign(hsm.Ctx, &req)
	if err != nil {
		return common.Hash{}.String(), err
	}

	return hex.EncodeToString(resp.Signature), nil
}

func (hsm *HsmClient) CreateKeyPair(projectID, locationID, keyRingID, keyID, method string) (string, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, locationID, keyRingID)
	var key *kmspb.CryptoKey
	if method == "ecdsa" {
		key = &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		}
	} else {
		key = &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096,
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
			},
		}
	}

	createdKey, err := hsm.Gclient.CreateCryptoKey(hsm.Ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: keyID,
		CryptoKey:   key,
	})
	if err != nil {
		log.Error("Failed to create ECDSA key: %v", err)
		return "", err
	}
	return createdKey.Name, nil
}
