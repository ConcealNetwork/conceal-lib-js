/** Stub so esbuild browser bundles do not resolve Node's `crypto` (nacl.js PRNG fallback). */
module.exports = {
  randomBytes() {
    throw new Error("Node crypto is not available in the browser prebuild bundle");
  },
};
