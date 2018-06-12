import Foundation

class Crypto {
    static let shared = Crypto()
    
    private init() {}
    
    func pbkdf2sha1(password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
        return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
    }
    
    func pbkdf2sha256(password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
        return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
    }
    
    func pbkdf2sha512(password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
        return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
    }
    
    private func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
        let passwordData = password.data(using: .utf8)!
        let saltData = salt.data(using: .utf8)!
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        
        var localDerivedKeyData = derivedKeyData
        
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            saltData.withUnsafeBytes { saltBytes in
                
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordData.count,
                    saltBytes, saltData.count,
                    hash,
                    UInt32(rounds),
                    derivedKeyBytes, localDerivedKeyData.count)
            }
        }
        if (derivationStatus != kCCSuccess) {
            print("Error: \(derivationStatus)")
            return nil;
        }
        
        return toHex(derivedKeyData)
    }
    
    private func toHex(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
}
