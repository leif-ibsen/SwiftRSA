//
//  Utilities.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 13/02/2022.
//

import XCTest

class Utilities: XCTestCase {

    // Convert a hex string to the corresponding byte array.
    static func hex2bytes(_ hex: String) -> Bytes {
        var b: Bytes = []
        var odd = false
        var x = Byte(0)
        var y = Byte(0)
        for c in hex {
            switch c {
            case "0" ... "9":
                x = c.asciiValue! - 48
            case "a" ... "f":
                x = c.asciiValue! - 87
            case "A" ... "F":
                x = c.asciiValue! - 55
            default:
                fatalError("hex2bytes")
            }
            if odd {
                b.append(y * 16 + x)
            } else {
                y = x
            }
            odd = !odd
        }
        if odd {
            fatalError("hex2bytes")
        }
        return b
    }
}
