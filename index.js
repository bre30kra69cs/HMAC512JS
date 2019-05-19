"use strict";

var R = require("ramda");

var SHA = require("sha512sha512"); //For easy way


var print = console.log; // VALUES

var BIN = 2;
var BYTE = 8;
var HEX = 16;
var ZERO = "00";
var BLOCKSIZE = 1024; // KEY COMPERING
//SHA-512 BigNumber array to byte array

var result2byteArray = R.pipe(R.map(function (x) {
  return x.toString(HEX);
}), R.map(function (x) {
  return R.repeat("0", HEX - x.length).join("") + x;
}), R.map(R.splitEvery(BIN)), R.reduce(R.concat, []));
//Padding zero to the right of key corresponding to blockSize

var keyPad = function keyPad(blockSize, key) {
  return key.concat(R.repeat(ZERO, (blockSize - key.length * BYTE) / BYTE));
};
//Key length bigger than blockSize


var keyLonger = R.curry(function (blockSize, key) {
  return key.length * BYTE > blockSize ? result2byteArray(SHA.SHA512(key)) : key;
}); //Key length shorter than blockSize

var keyShorter = R.curry(function (blockSize, key) {
  return key.length * BYTE < blockSize ? keyPad(blockSize, key) : key;
}); // PADDED KEY GENERATION
//Generation padded value for xor

var paddedValue = R.curry(function (value, blockSize) {
  return R.repeat(value, blockSize / BYTE);
});
var paddedValue5c = paddedValue("5c");
var paddedValue36 = paddedValue("36"); //Xor implementation of two bytes arrays

var xor = function xor(key, value) {
  return R.pipe(R.map(function (x) {
    return parseInt(x, HEX);
  }), R.zip(value.map(function (x) {
    return parseInt(x, HEX);
  })), R.map(function (x) {
    return x[0] ^ x[1];
  }), R.map(function (x) {
    return x.toString(HEX);
  }), R.map(function (x) {
    return R.repeat("0", BIN - x.length).join("") + x;
  }))(key);
};
//Generation padded 'outer key' and 'inner key'


var paddedKey = R.curry(function (blockSize, key) {
  return [xor(key, paddedValue5c(blockSize)), xor(key, paddedValue36(blockSize))];
}); // HASHING MESSAGE AND PADDED KEYS
//Hashing message

var hashMesge = R.curry(function (message, keys) {
  return R.pipe(R.concat(keys[1]), SHA.SHA512, result2byteArray, R.concat(keys[0]), SHA.SHA512)(message);
}); // MAIN FUNCTION
//HMAC process

var HMAC512 = R.curry(function (blockSize, key, message) {
  return R.pipe(keyLonger(blockSize), keyShorter(blockSize), paddedKey(blockSize), hashMesge(message))(key);
});
var HMAC = HMAC512(BLOCKSIZE);
//String to byte array

var str2byteArray = R.pipe(R.split(""), R.map(function (x) {
  return x.charCodeAt(0);
}), R.map(function (x) {
  return x.toString(16);
}));
var key1 = R.repeat("0b", 20);
var tex1 = str2byteArray("Hi There");

var key2 = R.repeat("aa", 20);
var tex2 = R.repeat("dd", 50);

var key3 = str2byteArray("Jefe");
var tex3 = str2byteArray("what do ya want for nothing?");

var key4 = R.range(1, 26).map(function (x) {
  return x.toString(16);
});
var tex4 = R.repeat("cd", 50);
// EXPORT MAIN FUNCTION

exports.print = SHA.result2print;
exports.HMAC512 = HMAC;
