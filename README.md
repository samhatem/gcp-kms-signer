# KMS Signer

A somewhat complete library for using Google KMS with Ethers.js.

Tests are currently set up with a GCP account that no longer exists so the test file will need to be updated to be run.

## Signer Documentation

Refer to ethers.js documentation for [Signers](https://docs.ethers.io/v5/api/signer/).

## Sending a Transaction

You can use `KmsSigner.sendTransaction(tx: TransactionRequest)` to send a transaction. Many of the properties on TransactionRequest are optional but in produciton its recommended that you set them explicitly if you have the available values to save the Signer from making additional network requests to set the values.

Values we recommend to set explicitly:
- maxFeePerGas
- maxPriorityFeePerGas
- nonce
- chainId

### Potential Gotchas

1. Google application credentials must including `Cloud KMS CryptoKey Signer` and `Cloud KMS CryptoKey Public Key Viewer`. More on KMS roles [here](https://cloud.google.com/kms/docs/reference/permissions-and-roles)

2. There's a default field on the key `destroyScheduledDuration: { seconds: '86400', nanos: 0 },` which sounds like KMS will destroy the key after that duration. This would contradicts GCP's [documentation](https://cloud.google.com/kms/docs/key-rotation#asymmetric) around asymmetric key rotation. We'll want to make sure that the keys we're using are never destroyed because that would result in a loss of our funds.

## Getting Started

### Install dependencies

`yarn` or `npm i`

### Build and watch for changes

`yarn start` or `npm run start`

### Create production bundle

`yarn build` or `npm run build`
