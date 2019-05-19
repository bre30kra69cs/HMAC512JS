# hmac512hmac512

Simple and understandable package of HMAC-SHA-512 implementation.
In fact is PRF-HMAC-SHA-512.

## Installation

```shell
$ npm install --save hmac512hmac512
```

In Node.js:
```js
// Load the full build.
var HMAC = require('hmac512hmac512');

// To get result as BigNumber.js array
//key and message is array of string with n length
//all string in array have hex-like face
let key = {"01", "02", "03", ..., "ff"}[n];
let message = {"01", "02", "03", ..., "ff"}[n];
var result = HMAC.HMAC512(key, message);

// To print result in human way view
HMAC.print(result);
```

Main ES6 JS file (where i implement this algorithm) placed
in src dir.

## Self PR

This package based on my prev npm package sha512sha512

Link: https://www.npmjs.com/package/sha512sha512

## Where did i get HMAC-SHA-512 description?

Test vector #1: "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512"

Paper name  #2: "Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec"

Paper name  #3: Wikipedia "HMAC"

Source #1: https://tools.ietf.org/pdf/rfc4231.pdf

Source #2: https://www.ietf.org/rfc/rfc4868.txt.pdf

Source #3: https://en.wikipedia.org/wiki/HMAC

Only because you so pretty, i place this files in "hmac512hmac512/docs".

## How to use

Use function print(HMAC512(hex-like string array)) and that's all. Very easy.

See the [package source](https://bitbucket.org/AndjeyS/cr-hmac-sha-512-js) for more details.

