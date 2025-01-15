# Cobo MPC Recovery Kits

Cobo MPC WaaS provides `Hard Key Recovery` for disaster recovery. The tool named `cobo-mpc-recovery-tool`
in this repository can reconstruct the MPC private key that corresponds to the Cobo MPC wallet.

Binary archives are published at https://github.com/CoboCustody/cobo-mpc-recovery-kits/releases

## Building the source

Building binary from the source in local environment, instead of using published binary archives

* Go 1.23 is required. Manually install Go, please [click here](https://go.dev/doc/install)

* Clone the repository:

```
git clone https://github.com/CoboCustody/cobo-mpc-recovery-kits.git
```
* Enter the directory
```
cd cobo-mpc-recovery-kits
```

* Build `cobo-mpc-recovery-tool`
```
make tool
```
Binary executable found in the `build` directory

## Commands

### Recovery command

Reconstruct all MPC key shares in TSS recovery group files, and derive the child private keys of all wallet addresses under the Cobo MPC wallet

```
cobo-mpc-recovery-tool [flags]
```
|         flags         | Description                                                                                                   |
|:---------------------:|---------------------------------------------------------------------------------------------------------------|
|       csv-file        | address csv file, contains HD derivation paths                                                                |
|    csv-output-dir     | address csv output dir, derive keys file output in this directory (default "recovery")                        |
|       group-id        | recovery group id                                                                                             |
| recovery-group-files  | TSS recovery group files, such as recovery/recovery-secrets-node1-time1,recovery/recovery-secrets-node2-time2 |
|         paths         | key HD derivation paths                                                                                       |
| show-root-private-key | show TSS root private key                                                                                     |

### Verify command

Verify all TSS recovery group files are valid

```
cobo-mpc-recovery-tool verify [flags]
```

|        flags         | Description                                                                                                   |
|:--------------------:|---------------------------------------------------------------------------------------------------------------|
|       group-id       | recovery group id                                                                                             |
| recovery-group-files | TSS recovery group files, such as recovery/recovery-secrets-node1-time1,recovery/recovery-secrets-node2-time2 |

### Derive command

Derive the child public key and addresses based on the paths and token

```
cobo-mpc-recovery-tool derive [flags]
```

| flags | Description             |
|:-----:|-------------------------|
|  key  | extended root key       |
| paths | key HD derivation paths |
| token | token                   |

## Running

* Prerequisites

  * Acquire TSS recovery group files (JSON format) that contain exported MPC key shares.
  * Passphrase of each TSS recovery group file

* Create a new recovery folder in the same directory level as `cobo-mpc-recovery-tool`, and paste the TSS recovery group files
under the recovery folder

```
├── cobo-mpc-recovery-tool
└── recovery
    ├── recovery-secrets-<nodeID1>-<time1>
    └── recovery-secrets-<nodeID2>-<time2>
```

* Execute the verify command

```
./cobo-mpc-recovery-tool verify \
    --recovery-group-files recovery/recovery-secrets-<nodeID1>-<time1>,recovery/recovery-secrets-<nodeID2>-<time2> \
    --group-id <groupID>
```

* (Optional) Locate the address.csv file after manually exporting the address information from Cobo Custody Web.
Please paste address.csv under the recovery folder
```
├── cobo-mpc-recovery-tool
└── recovery
    ├── address.csv
    ├── recovery-secrets-<nodeID1>-<time1>
    └── recovery-secrets-<nodeID2>-<time2>
```

* Execute the recovery command

Adding flag `--csv-file recovery/address.csv` or `--paths` are optional and alternative to recovery command

```
./cobo-mpc-recovery-tool \
    --recovery-group-files recovery/recovery-secrets-<nodeID1>-<time1>,recovery/recovery-secrets-<nodeID2>-<time2> \
    --group-id <groupID> \
    --show-root-private-key
```
The MPC root private key and the MPC root extended public key will be reconstructed and shown in logs.

* Once the execution completed, if flag `--csv-file recovery/address.csv` added, all child private keys will be saved
under the `recovery/address-recovery-<time>.csv` file in plain text.
Please make sure that all data stored securely.
