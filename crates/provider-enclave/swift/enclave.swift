import CryptoKit
import Foundation
import Security

// Payload: version(1) | blob_len(u16 BE) | SE key blob | ephemeral P-256 pub (x963, 65) | AES-GCM combined.
// The SE key blob is the CryptoKit dataRepresentation: encrypted to this machine's
// Secure Enclave, so only this device can load the key. No keychain item is used.
private let version: UInt8 = 1
private let info = Data("in.zemse.sophos-pin-oracle.enclave.v1".utf8)

private func accessControl() throws -> SecAccessControl {
    var err: Unmanaged<CFError>?
    // privateKeyUsage only: no .userPresence / .biometry flags, so no prompt.
    guard let ac = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &err)
    else { throw err!.takeRetainedValue() as Error }
    return ac
}

private func symmetricKey(_ shared: SharedSecret, _ eph: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: eph, sharedInfo: info, outputByteCount: 32)
}

private func emit(_ data: Data, _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ len: UnsafeMutablePointer<Int>) {
    let p = UnsafeMutablePointer<UInt8>.allocate(capacity: max(data.count, 1))
    data.copyBytes(to: p, count: data.count)
    out.pointee = p
    len.pointee = data.count
}

@_cdecl("se_free")
public func se_free(_ p: UnsafeMutablePointer<UInt8>?) { p?.deallocate() }

@_cdecl("se_available")
public func se_available() -> Int32 { SecureEnclave.isAvailable ? 1 : 0 }

/// Returns 0 on success (out = payload), 1 on failure (out = utf8 message).
@_cdecl("se_wrap")
public func se_wrap(_ seed: UnsafePointer<UInt8>, _ n: Int,
                    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ len: UnsafeMutablePointer<Int>) -> Int32 {
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl())
        let blob = key.dataRepresentation
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let sk = symmetricKey(try eph.sharedSecretFromKeyAgreement(with: key.publicKey), ephPub)
        let sealed = try AES.GCM.seal(Data(bytes: seed, count: n), using: sk)
        var d = Data([version, UInt8(blob.count >> 8), UInt8(blob.count & 0xff)])
        d.append(blob); d.append(ephPub); d.append(sealed.combined!)
        emit(d, out, len); return 0
    } catch {
        emit(Data("\(error)".utf8), out, len); return 1
    }
}

@_cdecl("se_unwrap")
public func se_unwrap(_ payload: UnsafePointer<UInt8>, _ n: Int,
                      _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ len: UnsafeMutablePointer<Int>) -> Int32 {
    do {
        let d = Data(bytes: payload, count: n)
        guard d.count > 3, d[0] == version else { throw NSError(domain: "enclave", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad payload header"]) }
        let bl = Int(d[1]) << 8 | Int(d[2])
        guard d.count > 3 + bl + 65 else { throw NSError(domain: "enclave", code: 2, userInfo: [NSLocalizedDescriptionKey: "truncated payload"]) }
        let blob = d.subdata(in: 3..<(3 + bl))
        let ephPub = d.subdata(in: (3 + bl)..<(3 + bl + 65))
        let ct = d.subdata(in: (3 + bl + 65)..<d.count)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        let eph = try P256.KeyAgreement.PublicKey(x963Representation: ephPub)
        let sk = symmetricKey(try key.sharedSecretFromKeyAgreement(with: eph), ephPub)
        let pt = try AES.GCM.open(AES.GCM.SealedBox(combined: ct), using: sk)
        emit(pt, out, len); return 0
    } catch {
        emit(Data("\(error)".utf8), out, len); return 1
    }
}
