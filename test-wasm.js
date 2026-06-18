import { encode_address } from './src/js/address.js';
import { base58_decode, base58_encode } from './src/js/address.js';
import { decode_address as wasm_decode_address } from './src/wasm/crypto/crypto.js';

async function test() {
  const spend = "1111111111111111111111111111111111111111111111111111111111111111";
  const view = "2222222222222222222222222222222222222222222222222222222222222222";
  const addr = encode_address(spend, view);
  
  const hex = base58_decode(addr);
  const hexMalleated = hex + "00000000";
  const addrMalleated = base58_encode(hexMalleated);
  
  try {
     const dec = wasm_decode_address(addrMalleated);
     console.log("WASM allowed malleated address", dec);
  } catch(e) {
     console.log("WASM threw:", e.message || e);
  }
}
test();
