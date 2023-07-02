declare module "fast-crc32c" {
    function calculate(digest: Uint8Array | string): number;

    export = { calculate };
}