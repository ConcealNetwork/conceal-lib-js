import { decode_address } from './src/js/address.js';

try {
  // A completely random short hex encoded as base58
  // base58 encoding of "d4f501" + "11" (which is too short)
  const hex = "d4f501" + "11".repeat(60) + "22".repeat(5); 
  const { base58_encode } = await import('./src/js/address.js');
  const shortAddr = base58_encode(hex);
  console.log("Short address:", shortAddr);
  decode_address(shortAddr);
  console.log("Decoded successfully? Should have thrown.");
} catch (e) {
  console.log("Error:", e.message);
}

try {
  const { base58_encode } = await import('./src/js/address.js');
  // Exactly 68 bytes hex + prefix -> spend, no view, no checksum
  const hex2 = "d4f501" + "11".repeat(32) + "22".repeat(10); 
  const shortAddr2 = base58_encode(hex2);
  decode_address(shortAddr2);
  console.log("Decoded successfully 2? Should have thrown.");
} catch (e) {
  console.log("Error 2:", e.message);
}
