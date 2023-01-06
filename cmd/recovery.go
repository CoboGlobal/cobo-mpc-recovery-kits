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

//nolint:cyclop
func recoveryPrivateKey() *bip32.Key {
	if len(GroupFiles) == 0 {
		log.Fatal("no group recovery files")
	}
	if GroupID == "" {
		log.Fatal("nil group ID")
	}
	recoveryGroups := make([]*tss.Group, 0)
	shares := make(tss.ECDSAShares, 0)

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
		share, err := group.ShareInfo.GenerateECDSAShare(key)
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

	privateKey, err := shares.ReconstructKey(int(threshold), crypto.S256())
	if err != nil {
		log.Fatalf("TSS group recovery failed to reconstruct root private key: %v", err)
	}

	chainCode, err := utils.Decode(recoveryGroup.GroupInfo.ChainCode)
	if err != nil {
		log.Fatalf("TSS group recovery failed to parse chaincode: %v", err)
	}

	// Create root extended private key
	extPrivateKey := &bip32.Key{
		Version:     bip32.PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         privateKey.D.Bytes(),
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}
	if ShowRootPrivate {
		log.Println("Reconstruct root private key:", utils.Encode(privateKey.D.Bytes()))
		log.Println("Reconstruct root extended private key:", extPrivateKey.String())
	}
	log.Println("Reconstruct root extended public key:", extPrivateKey.PublicKey().String())
	if recoveryGroup.GroupInfo.RootExtendedPubKey != extPrivateKey.PublicKey().String() {
		log.Fatalf("Reconstruct root extended public key mismatch")
	}
	return extPrivateKey
}

func deriveKey(key *bip32.Key) {
	if key == nil {
		log.Fatal("no extended key input")
	}
	// parse path
	if len(Paths) > 0 {
		for _, path := range Paths {
			if _, err := derive(key, path); err != nil {
				log.Fatalf("Derive path %v error: %v", path, err)
			}
		}
		return
	}
	// parse csv file
	if Csv == "" {
		return
	} else if _, err := os.Stat(Csv); err != nil {
		log.Fatalf("csv file %v state error: %v", Csv, err)
	}

	fileFullName := path.Base(Csv)
	fileType := path.Ext(fileFullName)
	fileName := strings.TrimSuffix(fileFullName, fileType)
	CsvOutputFile := strings.TrimSuffix(CsvOutputDir, "/") + "/" + fileName + "-recovery-" +
		time.Now().Format("20060102-150405") + fileType
	if _, err := os.Stat(CsvOutputFile); err == nil || os.IsExist(err) {
		log.Fatalf("File %v already exists, please backup and remove", CsvOutputFile)
	}

	log.Printf("Derive keys from %v to %v:", Csv, CsvOutputFile)
	if err := deriveKeyInCSV(key, Csv, CsvOutputFile); err != nil {
		log.Fatalf("Derive keys in csv file failed: %v", err)
	}
}

func derive(extendedKey *bip32.Key, path string) (deriveKey *bip32.Key, err error) {
	if path == "" {
		err = fmt.Errorf("path is nil")
		return
	}
	deriveKey = extendedKey
	indexes, err := getPath(path)
	if err != nil {
		return
	}
	for _, index := range indexes {
		deriveKey, err = deriveKey.NewChildKey(index)
		if err != nil {
			return
		}
	}
	if deriveKey.IsPrivate {
		log.Printf("Path: %v derive child private key: %v", path, utils.Encode(deriveKey.Key))
		log.Printf("Path: %v derive child extended private key: %v", path, deriveKey.String())
	}
	log.Printf("Path: %v derive child extended public key: %v", path, deriveKey.PublicKey().String())
	return
}

func getPath(path string) ([]uint32, error) {
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
			i = uint32(1<<31 + num)
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

//nolint:cyclop
func deriveKeyInCSV(extendedKey *bip32.Key, inputFile string, outputFile string) error {
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
		deriveKey, err := derive(extendedKey, wallet.HDPath)
		if err != nil {
			log.Errorf("Derive error: %v, wallet info: %v", err, wallet)
		}
		prv := ""
		prvExt := ""
		pubExt := ""
		if deriveKey != nil {
			if deriveKey.IsPrivate {
				prv = utils.Encode(deriveKey.Key)
				prvExt = deriveKey.String()
			}
			pubExt = deriveKey.PublicKey().String()
		}
		childPubKey := strings.TrimSpace(strings.ReplaceAll(wallet.ChildPubKey, " ", ""))
		if childPubKey != "" && pubExt != "" && childPubKey != pubExt {
			log.Warnf("Derive child public key mismatch, wallet info: %v", wallet)
		}
		// write to csv file
		writeLine := append(line, prv, prvExt, pubExt)
		if err := writer.Write(writeLine); err != nil {
			return fmt.Errorf("write derive keys error: %v", err)
		}
		writer.Flush()
	}
	log.Printf("Derive keys from %s to %s completed", inputFile, outputFile)
	return nil
}
