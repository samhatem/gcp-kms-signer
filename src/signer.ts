import { KeyManagementServiceClient } from "@google-cloud/kms";
import { JsonRpcProvider } from "@ethersproject/providers";
import { Signer } from "@ethersproject/abstract-signer";
import {
    arrayify,
    BytesLike,
    hexlify,
    joinSignature,
    Bytes,
} from "@ethersproject/bytes";
import { TransactionRequest, Provider } from "@ethersproject/abstract-provider";
import { resolveProperties } from "@ethersproject/properties";
import { UnsignedTransaction } from "@ethersproject/transactions";
import { hashMessage, _TypedDataEncoder } from "@ethersproject/hash";
import { TypedDataDomain, TypedDataField } from "@ethersproject/abstract-signer";
import { computeAddress, keccak256, serializeTransaction, getAddress } from "ethers/lib/utils";
import crc32c from "fast-crc32c";
import crypto from "crypto";

import { normalizeSignature, convertToEip155Signature, Signature } from "./signature";

class KmsSigner extends Signer {
    kmsClient: KeyManagementServiceClient;

    keyName: string;

    provider: JsonRpcMultiProvider;

    publicKey: Uint8Array | undefined;

    constructor(kmsClient: KeyManagementServiceClient, keyName: string, rpcEndpoint: string) {
        super();

        this.kmsClient = kmsClient;
        this.keyName = keyName;
        this.provider = new JsonRpcProvider(rpcEndpoint);
    }

    connect(provider: Provider): Signer {
        throw new Error("KmsSigner.connect() is not supported");
    }

    async getPublicKey(): Promise<Uint8Array> {
        if (this.publicKey) {
            return this.publicKey;
        }

        const [publicKey] = await this.kmsClient.getPublicKey({
            name: this.keyName,
        });

        // Optional, but recommended: perform integrity verification on publicKey.
        // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
        // https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (publicKey.name !== this.keyName) {
          throw new Error('GetPublicKey: request corrupted in-transit');
        }
        if (crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
          throw new Error('GetPublicKey: response corrupted in-transit');
        }

        // Get public key buffer from the pem format
        const p2 = crypto.createPublicKey(publicKey.pem as string)
        let pubKeyBuf = p2.export({format:"der", type:"spki"});
        pubKeyBuf = pubKeyBuf.slice(pubKeyBuf.length-65) // uncompressed public key starting with 0x04

        this.publicKey = pubKeyBuf;

        return pubKeyBuf;
    }

    async getAddress(): Promise<string> {
        const publicKeyBuf = await this.getPublicKey();

        const hexKey = hexlify(publicKeyBuf);

        return computeAddress(hexKey);
    }

    async asymmetricSignRequest(digest: Uint8Array): Promise<any> {
        const digestCrc32c = crc32c.calculate(digest);

        const [signResponse] = await this.kmsClient.asymmetricSign({
            name: this.keyName,
            digest: {
                sha256: digest,
            },
            digestCrc32c: {
                value: digestCrc32c,
            },
        });

        return signResponse;
    }

    async signDigest(_digest: BytesLike): Promise<Signature> {
        const digest = arrayify(_digest);

        const [signResponse, publicKey] = await Promise.all([
            this.asymmetricSignRequest(digest),
            this.getPublicKey(),
        ])

        // Optional, but recommended: perform integrity verification on signResponse.
        // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
        // https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (signResponse.name !== this.keyName) {
            throw new Error("AsymmetricSign: request corrupted in-transit");
        }
        if (!signResponse.verifiedDigestCrc32c) {
            throw new Error("AsymmetricSign: request corrupted in-transit");
        }
        if (crc32c.calculate(signResponse.signature as Uint8Array) !== Number(signResponse?.signatureCrc32c?.value)) {
            throw new Error("AsymmetricSign: response corrupted in-transit");
        }
      
        return normalizeSignature(signResponse.signature as Uint8Array, digest, publicKey)
    }

    async signTransaction(transaction: TransactionRequest): Promise<string> {
        return resolveProperties(transaction).then(async (tx) => {
            if (tx.from != null) {
                if (getAddress(tx.from) !== await this.getAddress()) {
                    throw new Error(`Transaction from address mismatch. transaction.from provided ${transaction.from}`);
                }
                delete tx.from;
            }

            const signature = convertToEip155Signature(
                await this.signDigest(keccak256(serializeTransaction(<UnsignedTransaction>tx))),
                transaction.chainId
            );

            return serializeTransaction(<UnsignedTransaction>tx, signature);
        });
    }

    async signMessage(message: Bytes | string): Promise<string> {
        return joinSignature(await this.signDigest(hashMessage(message)));
    }

    async _signTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>): Promise<string> {
        const populated = await _TypedDataEncoder.resolveNames(domain, types, value, (name: string) => {
            throw new Error("Unsupported operation. KMS Signer does not support resolving ENS names");
        });

        return joinSignature(await this.signDigest(_TypedDataEncoder.hash(populated.domain, types, populated.value)));
    }
}

export { KmsSigner };
