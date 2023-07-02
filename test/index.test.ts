import { KeyManagementServiceClient } from "@google-cloud/kms";
import { arrayify, recoverAddress, keccak256, verifyMessage, verifyTypedData } from "ethers/lib/utils";
import { expect } from "chai";

import { KmsSigner } from "../src/signer";

const endpoint = "https://polygon-mainnet.infura.io/v3/d8633a8d191140a19985f6757241f3ff";

describe("KMS Signer", function () {
    let kmsSigner: KmsSigner;

    let address: string;

    beforeEach(async () => {
        const projectId = "upheld-display-343001";
        const locationId = "us";
        const keyRingId = "relayer";
        const keyId = "test-key";
        
        // Instantiates a client
        const client = new KeyManagementServiceClient();

        const versionName = client.cryptoKeyVersionPath(
            projectId,
            locationId,
            keyRingId,
            keyId,
            "1"
        );

        kmsSigner = new KmsSigner(client, versionName, endpoint);

        address = await kmsSigner.getAddress();
    })

    it("signs a digest", async () => {
        const digest = keccak256(arrayify("0x24332242342342343429"))

        console.time("sign digest");
    
        const signature = await kmsSigner.signDigest(digest);

        console.timeEnd("sign digest");
    
        const recoveredAddress = recoverAddress(digest, signature);

        expect(recoveredAddress).to.equal(address);
    })

    it("signs a message", async () => {
        const message = "Hello World";

        console.time("sign message");

        const signature = await kmsSigner.signMessage(message);

        console.timeEnd("sign message");

        const recoveredAddress = verifyMessage(message,  signature);

        expect(recoveredAddress).to.equal(address);
    })

    it("signs typed data", async () => {
        // All properties on a domain are optional
        const domain = {
            name: 'Ether Mail',
            version: '1',
            chainId: 1,
            verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
        };
        
        // The named list of all type definitions
        const types = {
            Person: [
                { name: 'name', type: 'string' },
                { name: 'wallet', type: 'address' }
            ],
            Mail: [
                { name: 'from', type: 'Person' },
                { name: 'to', type: 'Person' },
                { name: 'contents', type: 'string' }
            ]
        };
        
        // The data to sign
        const value = {
            from: {
                name: 'Cow',
                wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'
            },
            to: {
                name: 'Bob',
                wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'
            },
            contents: 'Hello, Bob!'
        };

        console.time("sign typed data");

        const signature = await kmsSigner._signTypedData(domain, types, value);

        console.timeEnd("sign typed data");

        const recoveredAddress = verifyTypedData(domain, types, value, signature);

        expect(recoveredAddress).to.equal(address);
    })

    /*
    If used, need to rewrite this for mocha + chai instead of jest

    Must ensure that the signer has MATIC to run this test
    it("sends a transaction", async () => {
        jest.setTimeout(30000);

        const tx = await kmsSigner.sendTransaction({
            to: "0x183C7164e5F969258b98B3B9289384D15df3f958",
            value: "0x01",
            maxFeePerGas: BigNumber.from(10).pow(9).mul(600), // 600 gwei
            maxPriorityFeePerGas: BigNumber.from(10).pow(9).mul(30) // 30 gwei
        });

        const receipt = await tx.wait();

        console.log({ receipt });
    })
    */
})