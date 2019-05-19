const R = require("ramda");
const BigNumber = require("bignumber.js");
const SHA512 = require("sha512sha512");



//For easy way
let print = console.log;

let bn = x => new BigNumber(x);

let bn2 = x => new BigNumber(x, 2);

let bn16 = x => new BigNumber(x, 16);



//Support functions
let bin2bin64 = R.pipe(
    x => x.split(""),
    x => R.repeat("0", 64 - x.length).concat(x)
);

let bin2hex = R.pipe(
    x => x.join(""),
    x => parseInt(x, 2)
);

let bn2str = R.pipe(
    R.map(x => x.toString(2)),
    R.map(bin2bin64),
    R.map(R.splitEvery(8)),
    R.map(R.map(bin2hex)),
    R.reduce(R.concat, []),
    R.map(String.fromCharCode),
    R.reduce((x, y) => x + y, "")
);

let key2hash = (x, y) => x.length * 8 > y ? bn2str(SHA512.SHA512(x)) : x;


//Input setting
let bin2byte = x => R.repeat("0", 8 - x.length).concat(x);

let bin2qword = x => R.repeat("0", 64 - x.length).concat(x);

let sum = R.curry((x, y) => x + y);

let str2bin = R.pipe(
    R.split(""),
    R.map(x => x.charCodeAt(0)),
    R.map(bn),
    R.map(x => x.toString(2)),
    R.map(R.split("")),
    R.map(bin2byte),
    R.reduce(R.concat, [])
);

let bn2qword = R.pipe(
    x => x.toString(2),
    R.split(""),
    bin2qword
);

let sha2bin512 = R.pipe(
    R.map(bn2qword),
    R.reduce(R.concat, [])
);

let padKey = (x, y) => x.concat(R.repeat("0", y - x.length));

let keyLonger = R.curry((x, y) => y.length * 8 > x ? sha2bin512(SHA512.SHA512(y)) : str2bin(y));

let keyShorter = R.curry((x, y) => y.length < x ? padKey(y, x) : y);

let stateValue = R.curry((x, y) => R.pipe(
    z => z / 8,
    R.repeat(bin2byte(bn16(x).toString(2).split(""))),
    R.reduce(R.concat, [])
)(y));

let binXor = R.curry((x, y) => R.pipe(
    R.zip(y),
    R.map(z => z[0] === z[1] ? "0" : "1")
)(x));

let outerKey = (x, y) => R.pipe(
    stateValue("5c"),
    binXor(x),
)(y);

let innerKey = (x, y) => R.pipe(
    stateValue("36"),
    binXor(x)
)(y);



//Main functions
let key2str = R.pipe(
    R.splitEvery(64),
    R.map(R.join("")),
    R.map(bn2),
    bn2str,
);

let str2byteArray = x => x.split("").map(s => bn(s.charCodeAt(0)).toString(16));

let result2byteArray = R.pipe(
    R.map(x => x.toString(16)),
    R.map(R.splitEvery(2)),
    R.reduce(R.concat, [])
);

let key2byteArray = R.pipe(
    R.splitEvery(8),
    R.map(R.join("")),
    R.map(bn2),
    R.map(x => x.toString(16)),
    R.map(x => R.repeat("0", 2 - x.length) + x)
);

let hmac = (key, message, blockSize) => R.pipe(
    keyLonger(blockSize),
    keyShorter(blockSize),
    x => [outerKey(x, blockSize), innerKey(x, blockSize)],
    R.map(key2byteArray),
    x => SHA512.SHA512(x[0].concat(result2byteArray(SHA512.SHA512(x[1].concat(str2byteArray(message))))))
)(key);
let key1 = R.repeat(String.fromCharCode(0x0b), 20).join("");

let key2 = R.repeat(String.fromCharCode(0xaa), 20).join("");
let text2 = R.repeat(String.fromCharCode(0xdd), 50).join("");

let key3 = R.range(1, 26).map(x => String.fromCharCode(x)).join("");
let text3 = R.repeat(String.fromCharCode(0xcd), 50).join("");

let key4 = R.repeat(String.fromCharCode(0xaa), 131).join("");
let text4 = "Test Using Larger Than Block-Size Key - Hash Key First";

let key5 = R.repeat(String.fromCharCode(0xaa), 131).join("");
let text5 = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
SHA512.result2print(hmac(key5, text5, 1024));


let test = [
    bn16("d392b9a631704237"), bn16("c931e042fd4fd9bd"), bn16("8ecf25e9566fd1d0"), bn16("b1d094291629e0ee"),
    bn16("90ac01da30011558"), bn16("7749951e5ca377dd"), bn16("410a6c9eff5ec733"), bn16("1494f3f9cc1cc8a6")
];
