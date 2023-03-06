package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/tss"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip32"
)

type Wallet struct {
	Name         string
	Coin         string
	Address      string
	Memo         string
	AddressLabel string
	HDPath       string
	ChildPubKey  string
}

func recovery() {
	if len(GroupFiles) == 0 {
		log.Fatal("no group recovery files")
	}
	if GroupID == "" {
		log.Fatal("nil group ID")
	}
	recoveryGroups := make([]*tss.Group, 0)
	shares := make(tss.Shares, 0)

	for _, groupFile := range GroupFiles {
		_, err := os.Stat(groupFile)
		if err != nil {
			log.Fatalf("Group recovery file %v error: %v", groupFile, err)
		}

		groupBytes, err := ioutil.ReadFile(groupFile)
		if err != nil {
			log.Fatalf("Read group recovery file %v failed: %v", groupFile, err)
		}

		group := &tss.Group{}
		err = json.Unmarshal(groupBytes, group)
		if err != nil {
			log.Fatalf("Unmarshal group from recovery file %v failed: %v", groupFile, err)
		}
		if err := checkGroupParam(GroupID, group); err != nil {
			log.Fatalln("Group param check error:", err)
		}

		for _, recoveryGroup := range recoveryGroups {
			if err := checkMultiGroupsParam(recoveryGroup, group); err != nil {
				log.Fatalln("Multi groups param check error:", err)
			}
		}
		recoveryGroups = append(recoveryGroups, group)

		fmt.Printf("Enter password to decrypt share secret from %v\n", groupFile)
		key, err := cipher.Credentials("Password:")
		if err != nil {
			log.Fatalln("Credentials error:", err)
		}
		share, err := group.ShareInfo.GenerateShare(key)
		if err != nil {
			log.Fatalln("Group generate share error:", err)
		}
		shares = append(shares, share)
	}
	if len(recoveryGroups) == 0 {
		log.Fatal("Number of groups parse from files is 0")
	}
	recoveryGroup := recoveryGroups[0]
	threshold := recoveryGroup.GroupInfo.Threshold
	if int(threshold) > len(recoveryGroups) {
		log.Fatalf("Number of groups parse from files less than threshold %v", threshold)
	}
	if err := ReconstructAndDerivePrivate(recoveryGroup.GroupInfo, shares); err != nil {
		log.Fatal(err)
	}
}

func ReconstructAndDerivePrivate(gInfo *tss.GroupInfo, shares tss.Shares) error {
	curveType := crypto.CurveNameType[gInfo.Curve]
	threshold := int(gInfo.Threshold)
	chainCode, err := utils.Decode(gInfo.ChainCode)
	if err != nil {
		log.Fatalf("TSS group recovery failed to parse chaincode: %v", err)
	}

	switch curveType {
	case crypto.SECP256K1:
		privateKey, err := shares.ReconstructECDSAKey(threshold, crypto.S256())
		if err != nil {
			log.Fatalf("TSS group recovery failed to reconstruct root private key: %v", err)
		}
		extPrivateKey := crypto.CreateECDSAExtendedPrivateKey(chainCode, privateKey)
		if ShowRootPrivate {
			log.Println("Reconstructed root private key:", utils.Encode(privateKey.D.Bytes()))
			log.Println("Reconstructed root extended private key:", extPrivateKey.String())
		}
		log.Println("Reconstructed root extended public key:", extPrivateKey.PublicKey().String())
		if gInfo.RootExtendedPubKey != extPrivateKey.PublicKey().String() {
			log.Fatalf("reconstructed root extended public key mismatch")
		}

		if err := DeriveKey(extPrivateKey); err != nil {
			log.Fatalf("Failed to derive EDDSA key: %v", err)
		}
	case crypto.ED25519:
		privateKey, err := shares.ReconstructEDDSAKey(threshold, crypto.Edwards())
		if err != nil {
			log.Fatalf("TSS group recovery failed to reconstruct root private key: %v", err)
		}
		if ShowRootPrivate {
			log.Println("Reconstructed root private key:", utils.Encode(privateKey.GetD().Bytes()))
		}

		extPrivateKey := crypto.CreateEDDSAExtendedPrivateKey(privateKey, chainCode)
		log.Println("Reconstructed root extended public key:", extPrivateKey.PublicKey().String())
		if gInfo.RootExtendedPubKey != extPrivateKey.PublicKey().String() {
			log.Fatalf("reconstructed root extended public key mismatch")
		}

		if err := DeriveKey(extPrivateKey); err != nil {
			log.Fatalf("Failed to derive EDDSA key: %v", err)
		}
	default:
		log.Fatalf("not supported curve type: %v", curveType)
	}
	return nil
}

func DeriveKey(key interface{}) error {
	if key == nil {
		log.Fatal("no extended key input")
	}
	// parse path
	if len(Paths) > 0 {
		for _, path := range Paths {
			if _, err := Derive(key, path); err != nil {
				log.Fatalf("Derive path %v error: %v", path, err)
			}
		}
		return nil
	}
	// parse csv file
	if Csv == "" {
		return nil
	} else if _, err := os.Stat(Csv); err != nil {
		log.Fatalf("csv file %v state error: %v", Csv, err)
	}

	fileFullName := path.Base(Csv)
	fileType := path.Ext(fileFullName)
	fileName := strings.TrimSuffix(fileFullName, fileType)
	CsvOutputFile := strings.TrimSuffix(CsvOutputDir, "/") + "/" + fileName + "-recovery-" +
		time.Now().Format(time.RFC3339) + fileType
	if _, err := os.Stat(CsvOutputFile); err == nil || os.IsExist(err) {
		log.Fatalf("File %v already exists, please backup and remove", CsvOutputFile)
	}

	log.Printf("Derive keys from %v to %v:", Csv, CsvOutputFile)
	if err := DeriveKeyInCSV(key, Csv, CsvOutputFile); err != nil {
		log.Fatalf("Derive keys in csv file failed: %v", err)
	}
	return nil
}

func Derive(key interface{}, path string) (interface{}, error) {
	if path == "" {
		return nil, fmt.Errorf("path is nil")
	}
	indexes, err := GetPath(path)
	if err != nil {
		return nil, err
	}
	deriveKey := key
	switch deriveKey.(type) {
	case *bip32.Key:
		for _, index := range indexes {
			deriveKey, err = deriveKey.(*bip32.Key).NewChildKey(index)
		}
		if deriveKey.(*bip32.Key).IsPrivate {
			log.Printf("Path: %v derived child private key: %v", path, utils.Encode(deriveKey.(*bip32.Key).Key))
			log.Printf("Path: %v derived child extended private key: %v", path, deriveKey.(*bip32.Key).String())
		}
		log.Printf("Path: %v derived child extended public key: %v", path, deriveKey.(*bip32.Key).PublicKey().String())
	case *crypto.EDDSAExtendedKey:
		for _, index := range indexes {
			deriveKey, err = deriveKey.(*crypto.EDDSAExtendedKey).NewChildKey(index)
		}
		if deriveKey.(*crypto.EDDSAExtendedKey).IsPrivate {
			log.Printf("Path: %v derived child private key: %v", path, utils.Encode(deriveKey.(*crypto.EDDSAExtendedKey).Key))
			log.Printf("Path: %v derived child extended private key: %v", path, deriveKey.(*crypto.EDDSAExtendedKey).String())
		}
		log.Printf("Path: %v derived child extended public key: %v", path, deriveKey.(*crypto.EDDSAExtendedKey).PublicKey().String())
	default:
		return nil, fmt.Errorf("derive key error type")
	}
	return deriveKey, nil
}

func DeriveKeyInCSV(key interface{}, inputFile string, outputFile string) error {
	readFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("open %v failed: %v", inputFile, err)
	}

	writeFile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return fmt.Errorf("create and open %v failed: %v", outputFile, err)
	}
	defer readFile.Close()
	defer writeFile.Close()

	reader := csv.NewReader(readFile)
	writer := csv.NewWriter(writeFile)

	// title line
	line, err := reader.Read()
	if err != nil && err != io.EOF {
		return fmt.Errorf("read error: %v", err)
	}
	if line[0] == "wallet name" {
		writeTitle := append(line, "hex private key", "extended private key", "extended public key")
		err := writer.Write(writeTitle)
		if err != nil {
			return fmt.Errorf("write title error: %v", err)
		}
		writer.Flush()
	}

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read error: %v", err)
		}
		wallet := Wallet{
			Name:         line[0],
			Coin:         line[1],
			Address:      line[2],
			Memo:         line[3],
			AddressLabel: line[4],
			HDPath:       line[5],
			ChildPubKey:  line[6],
		}
		deriveKey, err := Derive(key, wallet.HDPath)
		if err != nil {
			log.Errorf("Derive error: %v, wallet info: %v", err, wallet)
		}
		prv := ""
		prvExt := ""
		pubExt := ""
		if deriveKey != nil {
			switch deriveKey.(type) {
			case *bip32.Key:
				if deriveKey.(*bip32.Key).IsPrivate {
					prv = utils.Encode(deriveKey.(*bip32.Key).Key)
					prvExt = deriveKey.(*bip32.Key).String()
				}
				pubExt = deriveKey.(*bip32.Key).PublicKey().String()
			case *crypto.EDDSAExtendedKey:
				if deriveKey.(*crypto.EDDSAExtendedKey).IsPrivate {
					prv = utils.Encode(deriveKey.(*crypto.EDDSAExtendedKey).Key)
				}
				pubExt = deriveKey.(*crypto.EDDSAExtendedKey).PublicKey().String()
			default:
				return fmt.Errorf("derive key error type")
			}
		}
		childPubKey := strings.TrimSpace(strings.ReplaceAll(wallet.ChildPubKey, " ", ""))
		if childPubKey != "" && pubExt != "" && childPubKey != pubExt {
			log.Warnf("Derived child public key mismatch, wallet info: %v", wallet)
		}
		// write to csv file
		writeLine := append(line, prv, prvExt, pubExt)
		if err := writer.Write(writeLine); err != nil {
			return fmt.Errorf("write derived keys error: %v", err)
		}
		writer.Flush()
	}
	log.Printf("Derive keys from %s to %s completed", inputFile, outputFile)
	return nil
}

func GetPath(path string) ([]uint32, error) {
	path = strings.TrimSpace(strings.ReplaceAll(path, " ", ""))
	path = strings.TrimPrefix(path, "m")
	path = strings.TrimPrefix(path, "/m")
	path = strings.TrimPrefix(path, "/")

	segments := strings.Split(path, "/")

	indexes := make([]uint32, 0)
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return nil, nil
	}

	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("segment nil")
		}
		var i uint32
		if strings.HasSuffix(segment, "'") || strings.HasSuffix(segment, "H") {
			num, err := strconv.Atoi(segment[:len(segment)-1])
			if err != nil {
				return nil, err
			}
			i = 1<<31 + uint32(num)
		} else {
			num, err := strconv.Atoi(segment)
			if err != nil {
				return nil, err
			}
			i = uint32(num)
		}
		indexes = append(indexes, i)
	}
	return indexes, nil
}
