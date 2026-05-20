export default nacl;
declare namespace nacl {
    namespace ll {
        export { ge_scalarmult_base };
        export { ge_scalarmult };
        export { ge_double_scalarmult_base_vartime };
        export { ge_add };
        export { ge_double_scalarmult_postcomp_vartime };
    }
    function randomBytes(n: any): Uint8Array<any>;
    function setPRNG(fn: any): void;
}
declare function ge_scalarmult_base(s: any): Uint8Array<ArrayBuffer>;
declare function ge_scalarmult(P: any, s: any): Uint8Array<ArrayBuffer>;
declare function ge_double_scalarmult_base_vartime(c: any, P: any, r: any): Uint8Array<ArrayBuffer>;
declare function ge_add(P: any, Q: any): Uint8Array<ArrayBuffer>;
declare function ge_double_scalarmult_postcomp_vartime(r: any, Pb: any, c: any, I: any): Uint8Array<ArrayBuffer>;
