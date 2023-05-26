package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/tss"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Wallet is a struct define address.csv file
// Version 0: wallet name, coin, address, memo, address label, HD path, child publickey
// Version 1: wallet name, coin, address, curve, memo, address label, HD path, child publickey.
type Wallet struct {
	Version     uint32
	AddressInfo *AddressInfo
}
type AddressInfo struct {
	Name        string
	Curve       string
	HDPath      string
	ChildPubKey string
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

		groupBytes, err := os.ReadFile(groupFile) //#nosec G304
		if err != nil {
			log.Fatalf("Read group recovery file %v failed: %v", groupFile, err)
		}

		group := &tss.Group{}
		err = json.Unmarshal(groupBytes, group)
		if err != nil {
			log.Fatalf("Unmarshal group from recovery file %v failed: %v", groupFile, err)
		}

		if GroupID != group.GroupInfo.ID {
			log.Fatalln("Group ID mismatch")
		}

		if err := group.CheckGroupParams(); err != nil {
			log.Fatalln("Group param check error:", err)
		}

		log.Printf("Verify group parameters passed!")
		for _, recoveryGroup := range recoveryGroups {
			if err := group.CheckWithGroup(recoveryGroup); err != nil {
				log.Fatalln("Multi groups param check error:", err)
			}
		}
		recoveryGroups = append(recoveryGroups, group)

		fmt.Printf("Enter password to decrypt share secret from %v\n", groupFile)
		key, err := cipher.Credentials("Password:")
		if err != nil {
			log.Fatalln("Credentials error:", err)
		}
		share, err := group.DecryptShare(key)
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
	key, err := recoveryGroup.ReconstructRootPrivateKey(shares)
	if err != nil {
		log.Fatal(err)
	}
	if err := DeriveKey(key); err != nil {
		log.Fatalf("Failed to derive key: %v", err)
	}
	if ShowRootPrivate {
		log.Println("Reconstructed root private key:", utils.Encode(key.GetKey()))
		log.Println("Reconstructed root extended private key:", key.String())
	}
	log.Println("Reconstructed root extended public key:", key.PublicKey().String())
}

func DeriveKey(key crypto.CKDKey) error {
	if key == nil {
		log.Fatal("no extended key input")
	}
	if len(Paths) > 0 {
		for _, path := range Paths {
			if _, err := crypto.Derive(key, path); err != nil {
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
	if err := CSVFileDerive(key, Csv, CsvOutputFile); err != nil {
		log.Fatalf("Derive keys in csv file failed: %v", err)
	}
	return nil
}

//nolint:gocognit
func CSVFileDerive(key crypto.CKDKey, inputFile string, outputFile string) error {
	readFile, err := os.Open(inputFile) //#nosec G304
	if err != nil {
		return fmt.Errorf("open %v failed: %v", inputFile, err)
	}

	writeFile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //#nosec G304
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
	wallet := Wallet{}
	if line[0] != "wallet name" {
		return fmt.Errorf("first line is not title in csv file")
	}
	if len(line) == 7 {
		wallet.Version = 0
	} else if len(line) == 8 && line[3] == "curve" {
		wallet.Version = 1
	} else {
		return fmt.Errorf("title line not recognized")
	}

	writeTitle := append(line, "hex private key", "extended private key", "extended public key")
	err = writer.Write(writeTitle)
	if err != nil {
		return fmt.Errorf("write title error: %v", err)
	}
	writer.Flush()

	// handle each line
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read error: %v", err)
		}
		switch wallet.Version {
		case 0:
			wallet.AddressInfo = &AddressInfo{
				Name:        line[0],
				Curve:       "secp256k1",
				HDPath:      line[5],
				ChildPubKey: line[6],
			}
		case 1:
			wallet.AddressInfo = &AddressInfo{
				Name:        line[0],
				Curve:       line[3],
				HDPath:      line[6],
				ChildPubKey: line[7],
			}
		default:
			return fmt.Errorf("error wallet version")
		}

		if key.GetType() == crypto.ECDSAKey && crypto.CurveNameType[wallet.AddressInfo.Curve] != crypto.SECP256K1 {
			continue
		}
		if key.GetType() == crypto.EDDSAKey && crypto.CurveNameType[wallet.AddressInfo.Curve] != crypto.ED25519 {
			continue
		}

		dk, err := crypto.Derive(key, wallet.AddressInfo.HDPath)
		if err != nil {
			return fmt.Errorf("address %v derive error: %v", wallet.AddressInfo, err)
		}
		childPubKey := strings.TrimSpace(strings.ReplaceAll(wallet.AddressInfo.ChildPubKey, " ", ""))
		if childPubKey != "" && dk.PublicKey().String() != "" && childPubKey != dk.PublicKey().String() {
			log.Warnf("Derived child public key mismatch, address info: %v", wallet.AddressInfo)
		}

		// write to csv file
		writeLine := append(line, utils.Encode(dk.GetKey()), dk.String(), dk.PublicKey().String())
		if err := writer.Write(writeLine); err != nil {
			return fmt.Errorf("write derived keys error: %v", err)
		}
		writer.Flush()
	}
	log.Printf("Derive keys from %s to %s completed", inputFile, outputFile)
	return nil
}
