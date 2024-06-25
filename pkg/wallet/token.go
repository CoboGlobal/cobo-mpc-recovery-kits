package wallet

import (
	"fmt"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
)

type Token struct {
	Name              string
	GenerateAddresses func(key crypto.CKDKey) ([]Address, error)
}

var (
	SMNT_MNT = Token{
		Name:              "SMNT_MNT",
		GenerateAddresses: GenerateEVMAddress,
	}

	MNT = Token{
		Name:              "MNT",
		GenerateAddresses: GenerateEVMAddress,
	}

	XTN = Token{
		Name:              "XTN",
		GenerateAddresses: GenerateXTNAddresses,
	}

	BTC = Token{
		Name:              "BTC",
		GenerateAddresses: GenerateBTCAddresses,
	}

	SETH = Token{
		Name:              "SETH",
		GenerateAddresses: GenerateEVMAddress,
	}

	ETH = Token{
		Name:              "ETH",
		GenerateAddresses: GenerateEVMAddress,
	}
)

var TokenMap = map[string]Token{
	SMNT_MNT.Name: SMNT_MNT,
	MNT.Name:      MNT,
	XTN.Name:      XTN,
	BTC.Name:      BTC,
	SETH.Name:     SETH,
	ETH.Name:      ETH,
}

func GetToken(name string) (Token, error) {
	if token, exists := TokenMap[name]; exists {
		return token, nil
	}
	return Token{}, fmt.Errorf("token %v not support", name)
}
