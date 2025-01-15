package wallet

import (
	"fmt"

	"github.com/CoboGlobal/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"
)

const (
	LEGACY        = "Legacy"
	NESTED_SEGWIT = "Nested SegWit (P2SH)"
	NATIVE_SEGWIT = "Native SegWit (Bech32)"
	TAPROOT       = "Taproot"
)

type Address struct {
	Type    string
	Address string
}

func PubKeyToBTCAddr(key crypto.CKDKey, network *chaincfg.Params) ([]Address, error) {
	if key == nil || network == nil {
		return nil, fmt.Errorf("network or key is nil")
	}

	if key.GetType() != crypto.ECDSAKey {
		return nil, fmt.Errorf("key is not ecdsa key")
	}

	publicKey, err := btcec.ParsePubKey(key.PublicKey().GetKey())
	if err != nil {
		return nil, err
	}
	pubBytes := publicKey.SerializeCompressed()

	var addresses []Address

	// LEGACY address
	p2pkh, err := btcutil.NewAddressPubKey(pubBytes, network)
	if err != nil {
		return addresses, err
	}
	addresses = append(addresses, Address{Type: LEGACY, Address: p2pkh.EncodeAddress()})

	// NATIVE_SEGWIT address
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubBytes), network)
	if err != nil {
		return addresses, err
	}
	addresses = append(addresses, Address{Type: NATIVE_SEGWIT, Address: p2wpkh.EncodeAddress()})

	// NESTED_SEGWIT address
	redeemScript, err := txscript.PayToAddrScript(p2wpkh)
	if err != nil {
		return addresses, err
	}
	p2sh, err := btcutil.NewAddressScriptHash(redeemScript, network)
	if err != nil {
		return addresses, err
	}
	addresses = append(addresses, Address{Type: NESTED_SEGWIT, Address: p2sh.EncodeAddress()})

	// TAPROOT address
	// p2tr, err := btcutil.NewAddressTaproot(txscript.ComputeTaprootKeyNoScript(publicKey).SerializeCompressed()[1:], network)
	p2tr, err := btcutil.NewAddressTaproot(publicKey.SerializeCompressed()[1:], network)
	if err != nil {
		return addresses, err
	}
	addresses = append(addresses, Address{Type: TAPROOT, Address: p2tr.EncodeAddress()})

	return addresses, nil
}

func GenerateXTNAddresses(key crypto.CKDKey) ([]Address, error) {
	network := &chaincfg.TestNet3Params
	return PubKeyToBTCAddr(key, network)
}

func GenerateBTCAddresses(key crypto.CKDKey) ([]Address, error) {
	network := &chaincfg.MainNetParams
	return PubKeyToBTCAddr(key, network)
}

func GenerateEVMAddress(key crypto.CKDKey) ([]Address, error) {
	if key == nil {
		return nil, fmt.Errorf("key is nil")
	}

	if key.GetType() != crypto.ECDSAKey {
		return nil, fmt.Errorf("key is not ecdsa key")
	}

	publicKey, err := crypto.DecompressECDSAPubKey(key.PublicKey().GetKey())
	if err != nil {
		return nil, err
	}
	return []Address{
		{
			Type:    "",
			Address: gethCrypto.PubkeyToAddress(*publicKey).Hex(),
		},
	}, nil
}
