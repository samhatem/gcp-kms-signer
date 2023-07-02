import { KeyManagementServiceClient } from "@google-cloud/kms";
import { ClientOptions } from "google-gax";

import { KmsSigner } from "./signer";

export type KeyPathOptions = {
    projectId: string;
    locationId: string;
    keyRingId: string;
    keyId: string;
}

/*
Some functionality we may want

- Get key rings based on location
- Get key ring ids
- get key ids
- get key versions

- create key ring
- create key
- create key version
*/

/*
Some exapmle functions I was using

async function createKeyRing() {
    const locationName = client.locationPath(projectId, locationId);

    const [keyRing] = await client.createKeyRing({
        parent: locationName,
        keyRingId,
    });

    console.log(`Created key ring: ${keyRing.name}`);
    return keyRing;
}

async function createKeyHsm() {
    const keyRingName = client.keyRingPath(projectId, locationId, keyRingId);

    const [key] = await client.createCryptoKey({
        parent: keyRingName,
        cryptoKeyId: keyId,
        cryptoKey: {
            purpose: "ASYMMETRIC_SIGN",
            versionTemplate: {
                algorithm: "EC_SIGN_SECP256K1_SHA256",
                protectionLevel: 2, // HSM
            },
        },
    });

    console.log({ key });

    console.log(`Created hsm key: ${key.name}`);
    return key;
}
*/

class KmsManager {
    kmsClient: KeyManagementServiceClient;

    keyPathOptions: KeyPathOptions;

    rpcEndpoint: string

    constructor(keyPathOptions: KeyPathOptions, rpcEndpoint: string, kmsClientOpts?: ClientOptions) {
        this.kmsClient = new KeyManagementServiceClient(kmsClientOpts);
        this.keyPathOptions = keyPathOptions;
        this.rpcEndpoint = rpcEndpoint;
    }

    getKmsSigner(versionId: string): KmsSigner {
        const versionName = this.kmsClient.cryptoKeyVersionPath(
            this.keyPathOptions.projectId,
            this.keyPathOptions.locationId,
            this.keyPathOptions.keyRingId,
            this.keyPathOptions.keyId,
            versionId,
        );

        return new KmsSigner(
            this.kmsClient,
            versionName,
            this.rpcEndpoint,
        );
    }
}

export { KmsManager };