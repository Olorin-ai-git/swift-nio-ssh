//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
@testable import NIOSSH
import XCTest

final class SSHEncryptedTrafficTests: XCTestCase {
    private var serializer: SSHPacketSerializer!
    private var parser: SSHPacketParser!

    private var buffer = ByteBufferAllocator().buffer(capacity: 1024)

    override func setUp() {
        self.serializer = SSHPacketSerializer()
        self.parser = SSHPacketParser(allocator: .init())

        self.assertPacketRoundTrips(.version("SSH-2.0-SwiftSSH_1.0"))
    }

    override func tearDown() {
        self.serializer = nil
        self.parser = nil
    }

    private func assertPacketRoundTrips(_ message: SSHMessage, file: StaticString = #filePath, line: UInt = #line) {
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: message, to: &self.buffer), file: file, line: line)
        self.parser.append(bytes: &self.buffer)

        var packet: SSHMessage?
        XCTAssertNoThrow(packet = try self.parser.nextPacket(), file: file, line: line)
        XCTAssertEqual(packet, message, file: file, line: line)
        XCTAssertNoThrow(XCTAssertNil(try self.parser.nextPacket(), file: file, line: line), file: file, line: line)
    }

    private func assertPacketRoundTripsDripFed(_ message: SSHMessage, file: StaticString = #filePath, line: UInt = #line) {
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: message, to: &self.buffer), file: file, line: line)

        var packet: SSHMessage?
        while var slice = self.buffer.readSlice(length: 1) {
            self.parser.append(bytes: &slice)
            XCTAssertNoThrow(packet = try self.parser.nextPacket(), file: file, line: line)

            if self.buffer.readableBytes > 0 {
                // More to come.
                XCTAssertNil(packet, file: file, line: line)
            } else {
                // Last one!
                XCTAssertEqual(packet, message, file: file, line: line)
            }
        }

        XCTAssertNoThrow(XCTAssertNil(try self.parser.nextPacket(), file: file, line: line), file: file, line: line)
    }

    private func assertPacketErrors(_ message: SSHMessage, file: StaticString = #filePath, line: UInt = #line) {
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: .serviceRequest(.init(service: "some service")), to: &self.buffer))
        self.parser.append(bytes: &self.buffer)

        XCTAssertThrowsError(try self.parser.nextPacket()) { error in
            print(error)
        }
    }

    private func protect(_ protection: Protection) {
        let (clientProtection, serverProtection) = protection.protections()
        self.serializer.addEncryption(clientProtection)
        self.parser.addEncryption(serverProtection)
    }

    func testBasicEncryptedPacketExchange() {
        self.protect(.aes128)
        self.assertPacketRoundTrips(.serviceRequest(.init(service: "some service")))
        self.assertPacketRoundTrips(.serviceAccept(.init(service: "some service")))
    }

    func testBasicExchangeAES256() {
        self.protect(.aes256)
        self.assertPacketRoundTrips(.serviceRequest(.init(service: "some service")))
        self.assertPacketRoundTrips(.serviceAccept(.init(service: "some service")))
    }

    func testDripFeedAES128() {
        self.protect(.aes128)
        self.assertPacketRoundTripsDripFed(.serviceRequest(.init(service: "some service")))
        self.assertPacketRoundTripsDripFed(.serviceAccept(.init(service: "some service")))
    }

    func testDripFeedAES256() {
        self.protect(.aes256)
        self.assertPacketRoundTripsDripFed(.serviceRequest(.init(service: "some service")))
        self.assertPacketRoundTripsDripFed(.serviceAccept(.init(service: "some service")))
    }

    func testRejectsCorruptedPacket() {
        self.protect(.aes128)
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: .serviceRequest(.init(service: "some service")), to: &self.buffer))

        // Mutate the buffer. We don't allow mutating the length because if we set the length to very long the parser returns nil instead.
        let index = (4 ..< self.buffer.writerIndex).randomElement()!
        let currentValue = self.buffer.getInteger(at: index, as: UInt8.self)!
        self.buffer.setInteger(currentValue ^ 0xFF, at: index) // Flip every bit
        self.parser.append(bytes: &self.buffer)

        XCTAssertThrowsError(try self.parser.nextPacket())
    }

    func testRejectsIncompatibleKeys() {
        let (clientProtection, _) = Protection.aes128.protections()
        let (_, serverProtection) = Protection.aes128.protections()
        self.serializer.addEncryption(clientProtection)
        self.parser.addEncryption(serverProtection)

        XCTAssertNoThrow(try self.serializer.serialize(message: .serviceRequest(.init(service: "some service")), to: &self.buffer))
        self.parser.append(bytes: &self.buffer)

        XCTAssertThrowsError(try self.parser.nextPacket())
    }

    func testEncryptedPacketLengthBoundsRejectInvalidLengths() throws {
        let maximumSize = SSHPacketParser.defaultMaximumPacketSize
        for cipher in [Protection.aes128, .aes256] {
            let (_, protection) = cipher.protections()
            let maximumLength = UInt32(maximumSize - protection.macBytes)
            for length in [maximumLength, maximumLength + 1, UInt32.max - UInt32(protection.macBytes), UInt32.max] {
                var parser = SSHPacketParser(allocator: ByteBufferAllocator())
                var version = ByteBuffer.of(string: "SSH-2.0-length-regression\r\n")
                parser.append(bytes: &version)
                XCTAssertNotNil(try parser.nextPacket())
                parser.addEncryption(protection)

                var header = ByteBufferAllocator().buffer(capacity: protection.cipherBlockSize)
                header.writeInteger(length)
                header.writeRepeatingByte(0, count: protection.cipherBlockSize - MemoryLayout<UInt32>.size)
                parser.append(bytes: &header)
                XCTAssertThrowsError(try parser.nextPacket()) { error in
                    XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
                }
            }
        }
    }

    func testEncryptedPacketLengthBelowLimitWaitsForRemainingBytes() throws {
        for cipher in [Protection.aes128, .aes256] {
            let (_, protection) = cipher.protections()
            var parser = SSHPacketParser(allocator: ByteBufferAllocator())
            var version = ByteBuffer.of(string: "SSH-2.0-length-regression\r\n")
            parser.append(bytes: &version)
            XCTAssertNotNil(try parser.nextPacket())
            parser.addEncryption(protection)

            var header = ByteBufferAllocator().buffer(capacity: protection.cipherBlockSize)
            header.writeInteger(UInt32(SSHPacketParser.defaultMaximumPacketSize - protection.macBytes - 1))
            header.writeRepeatingByte(0, count: protection.cipherBlockSize - MemoryLayout<UInt32>.size)
            parser.append(bytes: &header)
            XCTAssertNil(try parser.nextPacket())
            XCTAssertNil(try parser.nextPacket())
        }
    }

    func testInvalidMACLengthsThrowParserError() throws {
        let keys = NIOSSHSessionKeys(
            initialInboundIV: Array(repeating: 0, count: 12),
            initialOutboundIV: Array(repeating: 0, count: 12),
            inboundEncryptionKey: .init(size: .bits128),
            outboundEncryptionKey: .init(size: .bits128),
            inboundMACKey: .init(size: .bits128),
            outboundMACKey: .init(size: .bits128)
        )
        for macLength in [-1, Int.max] {
            let protection = try InvalidMACLengthProtection(initialKeys: keys, mac: nil)
            protection.configuredMACLength = macLength
            var parser = SSHPacketParser(allocator: ByteBufferAllocator())
            var version = ByteBuffer.of(string: "SSH-2.0-length-regression\r\n")
            parser.append(bytes: &version)
            XCTAssertNotNil(try parser.nextPacket())
            parser.addEncryption(protection)
            var header = ByteBuffer.of(bytes: Array(repeating: 0, count: protection.cipherBlockSize))
            parser.append(bytes: &header)
            XCTAssertThrowsError(try parser.nextPacket()) { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
            }
        }
    }

    func testSamplePacketFromTesting() throws {
        // This is a regression test from an early example that caused us some wrinkles.
        let keys = NIOSSHSessionKeys(initialInboundIV: [178, 178, 37, 48, 59, 189, 228, 147, 215, 24, 162, 20],
                                     initialOutboundIV: [156, 13, 118, 91, 255, 77, 47, 189, 62, 32, 93, 62],
                                     inboundEncryptionKey: .init(data: [241, 99, 181, 233, 148, 184, 187, 134, 80, 195, 18, 18, 218, 44, 118, 219, 120, 69, 225, 63, 105, 179, 131, 204, 156, 172, 105, 142, 12, 75, 148, 88]),
                                     outboundEncryptionKey: .init(data: [109, 86, 219, 88, 84, 20, 197, 13, 74, 19, 120, 17, 95, 59, 25, 181, 12, 237, 109, 51, 239, 86, 169, 53, 85, 35, 162, 88, 215, 199, 219, 82]),
                                     inboundMACKey: .init(size: .bits128), outboundMACKey: .init(size: .bits128))
        let protection = try assertNoThrowWithValue(AES256GCMOpenSSHTransportProtection(initialKeys: keys, mac: nil))

        self.parser.addEncryption(protection)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeBytes([0, 0, 0, 32, 49, 46, 121, 14, 95, 220, 77, 39, 178, 59, 26, 135, 163, 154, 166, 208, 209, 96, 3, 190, 205, 76, 105, 53, 20, 127, 211, 176, 54, 205, 52, 39, 30, 255, 128, 181, 87, 183, 49, 153, 6, 179, 118, 188, 204, 186, 249, 175])

        self.parser.append(bytes: &buffer)
        let packet = try assertNoThrowWithValue(self.parser.nextPacket())

        // The packet is temporarily nil because we don't understand it, but we will.
        XCTAssertEqual(packet, .serviceRequest(.init(service: "ssh-userauth")))
    }
}

private extension SSHEncryptedTrafficTests {
    enum Protection {
        case aes128
        case aes256

        fileprivate func protections() -> (client: NIOSSHTransportProtection, server: NIOSSHTransportProtection) {
            switch self {
            case .aes128:
                let protection = self.aes128Protection()
                return (client: protection.client, server: protection.server)
            case .aes256:
                let protection = self.aes256Protection()
                return (client: protection.client, server: protection.server)
            }
        }

        private func aes128Protection() -> (client: AES128GCMOpenSSHTransportProtection, server: AES128GCMOpenSSHTransportProtection) {
            let keys = self.generateKeys(keySize: .bits128, ivSize: 12, macSize: .bits128)
            let client = try! AES128GCMOpenSSHTransportProtection(initialKeys: keys, mac: nil)
            let server = try! AES128GCMOpenSSHTransportProtection(initialKeys: keys.inverted, mac: nil)
            return (client: client, server: server)
        }

        private func aes256Protection() -> (client: AES256GCMOpenSSHTransportProtection, server: AES256GCMOpenSSHTransportProtection) {
            let keys = self.generateKeys(keySize: .bits256, ivSize: 12, macSize: .bits128)
            let client = try! AES256GCMOpenSSHTransportProtection(initialKeys: keys, mac: nil)
            let server = try! AES256GCMOpenSSHTransportProtection(initialKeys: keys.inverted, mac: nil)
            return (client: client, server: server)
        }

        private func generateKeys(keySize: SymmetricKeySize, ivSize: Int, macSize: SymmetricKeySize) -> NIOSSHSessionKeys {
            NIOSSHSessionKeys(initialInboundIV: .init(randomBytes: ivSize),
                              initialOutboundIV: .init(randomBytes: ivSize),
                              inboundEncryptionKey: SymmetricKey(size: keySize),
                              outboundEncryptionKey: SymmetricKey(size: keySize),
                              inboundMACKey: SymmetricKey(size: macSize),
                              outboundMACKey: SymmetricKey(size: macSize))
        }
    }
}

private final class InvalidMACLengthProtection: TestTransportProtection {
    var configuredMACLength = 0
    override var macBytes: Int { self.configuredMACLength }
    override func decryptFirstBlock(_ source: inout ByteBuffer) throws {}
}
