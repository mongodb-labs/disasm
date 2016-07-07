/* 
 * Copyright 2016 MongoDB Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
var hexToBinMap = {
    "0": "0000",
    "1": "0001",
    "2": "0010",
    "3": "0011",
    "4": "0100",
    "5": "0101",
    "6": "0110",
    "7": "0111",
    "8": "1000",
    "9": "1001",
    "a": "1010",
    "A": "1010",
    "b": "1011",
    "B": "1011",
    "c": "1100",
    "C": "1100",
    "d": "1101",
    "D": "1101",
    "e": "1110",
    "E": "1110",
    "f": "1111",
    "F": "1111"
}

var binToHexMap = {
    "0000": "0",
    "0001": "1",
    "0010": "2",
    "0011": "3",
    "0100": "4",
    "0101": "5",
    "0110": "6",
    "0111": "7",
    "1000": "8",
    "1001": "9",
    "1010": "a",
    "1011": "b",
    "1100": "c",
    "1101": "d",
    "1110": "e",
    "1111": "f"
}

// TODO: Add conversions for 8-bit, 16-bit, and 32-bit values
$(function() {
    $.contextMenu({
        selector: '.number',
        items: {
            hex: {
                name: "Hexadecimal"
            },
            unsignedDec64: {
                name: "64-bit Unsigned Decimal"
            },
            twosCompDec64: {
                name: "64-bit Signed 2's Complement Decimal"
            },
            binary: {
                name: "Binary"
            }
        },
        callback: contextMenuConvertBase
    });
});

function contextMenuConvertBase(key, opt) {
    var base = opt.$trigger.context.getAttribute("value");
    if (key == base) {
        console.log("Number is unchanged");
        return; 
    }
    // var radix;
    var binString;
    var startVal = opt.$trigger.context.innerHTML;
    var newVal;
    switch(base) {
        case "hex":
            binString = hexToBin(startVal);
            break;
        case "unsignedDec64":
            binString = unsignedDecToBin(startVal, 64);
            break;
        case "twosCompDec64":
            binString = signedDecToBin(startVal, 64);
            break;
        case "binary":
            binString = startVal;
            break;
        default:
            throw new Error("Unexpected base type: " + base);
    }
    switch (key) {
        case "hex":
            newVal = binToHex(binString);
            break;
        case "unsignedDec64":
            newVal = binToUnsignedDec(binString, 64);
            break;
        case "twosCompDec64":
            newVal = binToSignedDec(binString, 64);
            break;
        case "binary":
            newVal = binString;
            break;
        default:
            throw new Error("Unexpected key type: " + key);
    }
    opt.$trigger.context.setAttribute("value", key);
    if (key == "hex") {
        newVal = "0x" + newVal; 
    }
    opt.$trigger.context.innerHTML = newVal;
    console.log("Converted " + base + " number " + startVal + " to binary number " + binString + " to " + key + " number " + newVal);
}

function hexToBin(val) {
    var binStr = ""
    for (var i = 2; i < val.length; i++) {
        binStr += hexToBinMap[val.charAt(i)];
    }
    return binStr;
}

function binToHex(val) {
    var hexStr = "";
    // Make the binary string length divisible by 4 by prepending it with 0's
    for (var i = val.length % 4; i > 0; i--) {
        val = "0" + val;
    }
    for (var i = 0; i < val.length; i += 4) {
        hexStr += binToHexMap[val.substring(i, i+4)];
    }
    return hexStr;
}

function unsignedDecToBin(val, bits) {
    var decVal = BigInteger(val);
    var divRem;
    var binVal = "";
    for (var i = 0; i < bits; i++) {
        divRem = decVal.divRem(2);
        binVal = divRem[1] + binVal;
        decVal = divRem[0];
    }
    return binVal;
}

function binToUnsignedDec(val, bits) {
    var decVal = BigInteger.ZERO;
    for (var i = bits - val.length; i > 0; i--) {
        val = "0" + val;
    }
    // http://stackoverflow.com/questions/10258828/how-to-convert-binary-string-to-decimal
    return val.split('').reverse().reduce(function(x,y,i) {
        return (y === '1') ? x.add(BigInteger(2).pow(i)) : x;
    }, BigInteger.ZERO).toString();
}

function signedDecToBin(val, bits) {
    var negative = false;
    if (val.charAt(0) == '-') {
        negative = true;
        val = val.substring(1,substring.length);
    }
    var unsignedBinVal = unsignedDecToBin(val, bits);
    var twosCompBin = negative ? applyTwosCompConversion(unsignedBinVal) : unsignedBinVal;
    return twosCompBin;
}

function binToSignedDec(val, bits) {
    var signBit = val.charAt(0);
    var unsignedBinVal = "";
    for (var i = bits - val.length; i > 0; i--) {
        val = signBit + val;
    }
    var unsignedBinVal = signBit == "1" ? applyTwosCompConversion(val) : val;
    return (signBit == "1" ? "-" : "") + binToUnsignedDec(unsignedBinVal, bits);
}

function applyTwosCompConversion(val) {
    var i;
    var carried = false;
    var converted = "";
    for (i = val.length-1; i >= 0; i--) {
        if (val.charAt(i) == "1") {
            if (carried)
                converted = "0" + converted;
            else {
                converted = "1" + converted;
                carried = true;
            }
        } 
        else {
            if (carried)
                converted = "1" + converted;
            else
                converted = "0" + converted;
        }
    }
    return converted;
}

/*
 * Given a binary string val, change its length if legal.
 */
function changeLength(val, length) {
    if (val.length > length)
        return trim(val, length);
    else if (val.length < length)
        return extend(val, length);
    else
        return val;
}

function trim(val, length) {
    var signBit = val.charAt(0);
    var i;
    for (i = 1; i <= val.length - length; i++) {
        if (signBit !== val.charAt(i)) {
            alert("Cannot shrink this number, because doing so would result in precision/data loss");
            return val;
        }
    }
    return val.substring(val.length - length, val.length);
}

/*
 * Bug (?): Assumes the binary string is aligned. That is, for example, if the binary string
 *      "10000" is passed in, it will be assumed to be a negative number, and will have the number
 *      "1" extended.
 */
function extend(val, length) {
    var signBit = val.charAt(0);
    var signExtension = "";
    for (var i = 0; i < bits - val.length; i++) {
        signExtension = signBit + signExtension;
    }
    return signExtension + val;
}