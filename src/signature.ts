import { ecdsaRecover, signatureImport, signatureNormalize } from "secp256k1";
import { hexlify } from "@ethersproject/bytes";

export type Signature = { r: string, s: string, v: number, recoveryParam: number }

function calculateRecoveryId(signature: Uint8Array, hash: Uint8Array, uncompressPubKey: Uint8Array): number {
    let recId = -1;

    for (let i = 0; i < 4; i++) {
        // try with a recoveryId of i
        const rec = ecdsaRecover(signature, i, hash, false);
        if (Buffer.compare(rec, uncompressPubKey) === 0) {
            recId = i;
            break;
        }
    }
    if (recId === -1) throw new Error("Impossible to calculare the recovery id. should not happen");
    return recId;
}

function calculateV(recovery: number, chainId?: number): number {
    if (!chainId || typeof chainId === "number") {
        // return legacy type ECDSASignature (deprecated in favor of ECDSASignatureBuffer to handle large chainIds)
        if (chainId && !Number.isSafeInteger(chainId)) {
            throw new Error(
                "The provided number is greater than MAX_SAFE_INTEGER (please use an alternative input type)",
            );
        }

        const v = chainId ? recovery + (chainId * 2 + 35) : recovery + 27;
        return v;
    }
    throw new Error("Other chainId type not implemented");
}

export function convertToEip155Signature(signature: Signature, chainId?: number): Signature {
    signature.v = calculateV(signature.recoveryParam, chainId);

    return signature;
}

export function normalizeSignature(signature: Uint8Array, digest: Uint8Array, publicKey: Uint8Array, chainId?: number): Signature {
            // Very important, lost a lot of time on it, convert the returned signature into a 64 bytes long valid signature
        let _64 = signatureImport(signature);
        // this is to get the low part of the curve
        const normalized = signatureNormalize(_64); 
        const r = hexlify(normalized.slice(0, 32))
        const s = hexlify(normalized.slice(32, 64))
        // this is to find the appropriate recovery id (below)
        const recId = calculateRecoveryId(normalized, digest, publicKey); 
        // to embed into the recovery id the chain ID for EIP-155
        const v = recId + 27;

        return { r, s, v, recoveryParam: recId };
}