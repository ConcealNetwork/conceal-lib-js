import { encode_address, decode_address } from './src/js/address.js';
import { base58_decode, base58_encode } from './src/js/address.js';

const spend = "1111111111111111111111111111111111111111111111111111111111111111";
const view = "2222222222222222222222222222222222222222222222222222222222222222";

const addr = encode_address(spend, view);
console.log("Original:", addr);

const hex = base58_decode(addr);
console.log("Hex:", hex);

const hexMalleated = hex + "00000000";
const addrMalleated = base58_encode(hexMalleated);
console.log("Malleated:", addrMalleated);

const decoded = decode_address(addrMalleated);
console.log("Decoded spend:", decoded.spend);
console.log("Decoded view:", decoded.view);

console.log("Match original spend?", decoded.spend === spend);
console.log("Match original view?", decoded.view === view);
