# Cobo MPC Recovery Kits

Cobo MPC WaaS provides `Hard Key Recovery` for disaster recovery. The tool named `cobo-mpc-recovery-tool`
in this repository can reconstruct the MPC private key that corresponds to the Cobo MPC wallet.
Binary archives are published at https://github.com/CoboCustody/cobo-mpc-recovery-kits/releases

## Building the source

* Go 1.18 is required. Manually install Go, please [click here](https://go.dev/doc/install)

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

Reconstruct all MPC key shares in TSS group recovery files, and derive the child private keys of all wallet addresses under the Cobo MPC wallet

```
cobo-mpc-recovery-tool [flags]
```
|         flags         | Description                                                                                             |
|:---------------------:|---------------------------------------------------------------------------------------------------------|
|       csv-file        | address csv file, contains HD derivation paths                                                          |
|    csv-output-dir     | address csv output dir, derive keys file output in this directory (default "recovery")                  |
|       group-id        | recovery group id                                                                                       |
| group-recovery-files  | TSS group recovery files, such as recovery/tss-group-id-node-1-time1,recovery/tss-group-id-node-2-time2 |
|         paths         | key HD derivation paths                                                                                 |
| show-root-private-key | show TSS root private key                                                                               |

### Verify command

Verify all TSS group recovery files are valid

```
cobo-mpc-recovery-tool verify [flags]
```

|        flags         | Description                                                                                             |
|:--------------------:|---------------------------------------------------------------------------------------------------------|
|       group-id       | recovery group id                                                                                       |
| group-recovery-files | TSS group recovery files, such as recovery/tss-group-id-node-1-time1,recovery/tss-group-id-node-2-time2 |

## Running

* Prerequisites

  * Acquire TSS group recovery files (JSON format) that contain exported MPC key shares.
  * Passphrase of each TSS group recovery file

* Create a new recovery folder in the same directory level as `cobo-mpc-recovery-tool`, and paste the TSS group recovery files
under the recovery folder

```
├── cobo-mpc-recovery-tool
└── recovery
    ├── tss-group-<GROUP_ID>-node-<NODE_ID1>-recovery-<TIME1>
    └── tss-group-<GROUP_ID>-node-<NODE_ID2>-recovery-<TIME2>
```

* Execute the verify command

```
./cobo-mpc-recovery-tool verify \
    --group-recovery-files recovery/tss-group-<GROUP_ID>-node-<NODE_ID1>-recovery-<TIME1>,recovery/tss-group-<GROUP_ID>-node-<NODE_ID2>-recovery-<TIME2> \
    --group-id <GROUP_ID>
```

* (Optional) Locate the address.csv file after manually exporting the address information from Cobo Custody Web.
Please paste address.csv under the recovery folder
```
├── cobo-mpc-recovery-tool
└── recovery
    ├── address.csv
    ├── tss-group-<GROUP_ID>-node-<NODE_ID1>-recovery-<TIME1>
    └── tss-group-<GROUP_ID>-node-<NODE_ID2>-recovery-<TIME2>
```

* Execute the recovery command

Adding flag `--csv-file recovery/address.csv` or `--paths` are optional and alternative to recovery command

```
./cobo-mpc-recovery-tool \
    --group-recovery-files recovery/tss-group-<GROUP_ID>-node-<NODE_ID1>-recovery-<TIME1>,recovery/tss-group-<GROUP_ID>-node-<NODE_ID2>-recovery-<TIME2> \
    --group-id <GROUP_ID> \
    --show-root-private-key
```
The MPC root private key and the MPC root extended public key will be reconstructed and shown in logs.

* Once the execution completed, if flag `--csv-file recovery/address.csv` added, all child private keys will be saved
under the `recovery/address-recovery-<TIME>.csv` file in plain text.
Please make sure that all data stored securely.
