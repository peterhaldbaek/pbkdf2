import XCTest
@testable import PBKDF2

class CryptoTests: XCTestCase {
    
    func testPBKDF2() {
        let expected = "edf738254821c55da61e6afa20efd0c657cb941c"
        let result = Crypto.shared.pbkdf2sha1(password: "password", salt: "salt", keyByteCount: 20, rounds: 5000)
        XCTAssertEqual(result, expected)
    }
}
