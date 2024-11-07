# Demo

This demo shows how to derive a deposit addresses from an address' deposit metadata and the base deposit public key. 

## Derive the deposit address

You will need the following to derive the deposit addresses:
- The deposit address metadata from the Lombard public API. For mainnet, all the paginated deposit addresses are availalbe at https://mainnet.prod.lombard.finance/api/v1/address. To get a specific address, like that in our example, you can go to https://mainnet.prod.lombard.finance/api/v1/address?to_address=0x57F9672bA603251C9C03B36cabdBBcA7Ca8Cfcf4&to_blockchain=DESTINATION_BLOCKCHAIN_ETHEREUM&limit=1&offset=0&asc=false&referralId=lombard.
- The Lombard base deposit public key. Lombard's base deposit key is stored on Cubist on and for each environment, we can provide you its public key. You must configure this in `config.yaml` by following the instructions below.

### 1. Configure

Set the following values in your `config.yaml`

| Config          | Description                                                | Example            |
|-----------------|------------------------------------------------------------|--------------------|
| demo.public-key | The public key of Lombard's base deposit key on Cubist.  | `0x...`     |


### 2. Derive the address
```bash
go run demo/cmd/derive/main.go
```


If the derivation is successful, the outpu will look like
```shell
Address: bc1q29nrqh3cj5q5r0n7yjea6hezkrxhf6nyfv3afz
Addresses match
```