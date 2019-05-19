const R = require("ramda");
const SHA = require("sha512sha512");



//For easy way
let print = console.log;



// VALUES

const BIN = 2;

const BYTE = 8;

const HEX = 16;

const ZERO = "00";

let BLOCKSIZE = 1024;



// KEY COMPERING

//SHA-512 BigNumber array to byte array
let result2byteArray = R.pipe(
    R.map(x => x.toString(HEX)),
    R.map(x => R.repeat("0", HEX - x.length).join("") + x),
    R.map(R.splitEvery(BIN)),
    R.reduce(R.concat, [])
);

//Padding zero to the right of key corresponding to blockSize
let keyPad = (blockSize, key) => key.concat(R.repeat(ZERO, (blockSize - key.length * BYTE) / BYTE));

//Key length bigger than blockSize
let keyLonger = R.curry((blockSize, key) => key.length * BYTE > blockSize ? result2byteArray(SHA.SHA512(key)) : key);

//Key length shorter than blockSize
let keyShorter = R.curry((blockSize, key) => key.length * BYTE < blockSize ? keyPad(blockSize, key) : key);



// PADDED KEY GENERATION

//Generation padded value for xor
let paddedValue = R.curry((value, blockSize) => R.repeat(value, blockSize / BYTE));

let paddedValue5c = paddedValue("5c");

let paddedValue36 = paddedValue("36");

//Xor implementation of two bytes arrays
let xor = (key, value) => R.pipe(
    R.map(x => parseInt(x, HEX)),
    R.zip(value.map(x => parseInt(x, HEX))),
    R.map(x => x[0] ^ x[1]),
    R.map(x => x.toString(HEX)),
    R.map(x => R.repeat("0", BIN - x.length).join("") + x)
)(key);

//Generation padded 'outer key' and 'inner key'
let paddedKey = R.curry((blockSize, key) => [xor(key, paddedValue5c(blockSize)), xor(key, paddedValue36(blockSize))]);



// HASHING MESSAGE AND PADDED KEYS

//Hashing message
let hashMesge = R.curry((message, keys) => R.pipe(
    R.concat(keys[1]),
    SHA.SHA512,
    result2byteArray,
    R.concat(keys[0]),
    SHA.SHA512
)(message));



// MAIN FUNCTION

//HMAC process
let HMAC512 = R.curry((blockSize, key, message) => R.pipe(
    keyLonger(blockSize),
    keyShorter(blockSize),
    paddedKey(blockSize),
    hashMesge(message)
)(key));

let HMAC = HMAC512(BLOCKSIZE);



// TEST OF WORK

//String to byte array
let str2byteArray = R.pipe(
    R.split(""),
    R.map(x => x.charCodeAt(0)),
    R.map(x => x.toString(16))
);

let key1 = R.repeat("0b", 20);
let tex1 = str2byteArray("Hi There");

let key2 = R.repeat("aa", 20);
let tex2 = R.repeat("dd", 50);

let key3 = str2byteArray("Jefe");
let tex3 = str2byteArray("what do ya want for nothing?");

let key4 = R.range(1, 26).map(x => x.toString(16));
let tex4 = R.repeat("cd", 50);



// EXPORT MAIN FUNCTION

exports.print = SHA.result2print;
exports.HMAC512 = HMAC;
