package protobuf

import "errors"

type CryptoKey string

const (
	ECDSA CryptoKey = "ecdsa"
	EDDSA CryptoKey = "eddsa"
)

func ParseTransactionType(s string) (CryptoKey, error) {
	switch s {
	case string(ECDSA):
		return ECDSA, nil
	case string(EDDSA):
		return EDDSA, nil
	default:
		return "", errors.New("unknown transaction type")
	}
}
