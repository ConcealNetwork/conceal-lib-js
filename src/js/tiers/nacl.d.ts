declare const nacl: {
    ll: {
        ge_scalarmult_base: (s: any) => Uint8Array<ArrayBuffer>;
        ge_scalarmult: (P: any, s: any) => Uint8Array<ArrayBuffer>;
        ge_double_scalarmult_base_vartime: (c: any, P: any, r: any) => Uint8Array<ArrayBuffer>;
        ge_add: (P: any, Q: any) => Uint8Array<ArrayBuffer>;
        ge_double_scalarmult_postcomp_vartime: (r: any, Pb: any, c: any, I: any) => Uint8Array<ArrayBuffer>;
    };
    randomBytes: (n: any) => Uint8Array<any>;
    setPRNG: (fn: any) => void;
};
export default nacl;
