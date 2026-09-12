//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import XCTest

@testable import NIOSSH

final class NIOSSHSignatureTests: XCTestCase {
    func testCurveWidthsAndSignPadding() throws {
        for (identifier, width) in [("ecdsa-sha2-nistp256", 32), ("ecdsa-sha2-nistp384", 48), ("ecdsa-sha2-nistp521", 66)] {
            let scalar = Array(repeating: UInt8(1), count: width)
            for component in [scalar, [UInt8(0)] + scalar] {
                var valid = ecdsaSignatureBuffer(identifier: identifier, r: component, s: component)
                XCTAssertNotNil(try valid.readSSHSignature(), identifier)
            }
            for oversized in [scalar + [UInt8(1)], [UInt8(0)] + scalar + [UInt8(1)]] {
                for (r, s) in [(oversized, scalar), (scalar, oversized)] {
                    var invalid = ecdsaSignatureBuffer(identifier: identifier, r: r, s: s)
                    XCTAssertThrowsError(try invalid.readSSHSignature(), identifier) { error in
                        XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
                    }
                }
            }
        }
    }

    /// Builds the wire representation of an ECDSA signature with attacker-chosen `r` and `s` values.
    ///
    /// Format is `string signature-identifier` followed by `string(mpint r || mpint s)`, matching what
    /// `readECDSAP*Signature()` expects.
    private func ecdsaSignatureBuffer(identifier: String, r: [UInt8], s: [UInt8]) -> ByteBuffer {
        var inner = ByteBufferAllocator().buffer(capacity: r.count + s.count + 8)
        inner.writeSSHString(r)
        inner.writeSSHString(s)

        var buffer = ByteBufferAllocator().buffer(capacity: inner.readableBytes + identifier.utf8.count + 8)
        buffer.writeSSHString(Array(identifier.utf8))
        buffer.writeSSHString(&inner)
        return buffer
    }

    func testOversizedECDSARComponentIsRejected() throws {
        // `r` is far wider than the P-256 point size (32 bytes). Leading byte is non-zero so `mpIntView`
        // does not strip it, keeping the length oversized.
        var buffer = self.ecdsaSignatureBuffer(
            identifier: "ecdsa-sha2-nistp256",
            r: Array(repeating: 0x01, count: 4096),
            s: Array(repeating: 0x02, count: 32)
        )

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testOversizedECDSASComponentIsRejected() throws {
        var buffer = self.ecdsaSignatureBuffer(
            identifier: "ecdsa-sha2-nistp256",
            r: Array(repeating: 0x01, count: 32),
            s: Array(repeating: 0x02, count: 4096)
        )

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }
}
