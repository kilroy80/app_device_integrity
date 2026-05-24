import Foundation
import DeviceCheck
import CryptoKit

//public func print(_ object: Any...) {
//    #if DEBUG
//    for item in object {
//        Swift.print(object)
//    }
//    #endif
//}
//
//public func print(_ object: Any) {
//    #if DEBUG
//    Swift.print(object)
//    #endif
//}

@available(iOS 14.0, *)

final class AppDeviceIntegrity {
    let inputString: String
    var attestationString: String?
    private let keyName = "AppAttestKeyIdentifier"
    private let attestService = DCAppAttestService.shared
    private let userDefaults = UserDefaults.standard
    private var keyID: String? {
        didSet
        {
//             print("🐝 Key ID:", keyID!)
        }
    }
    
    init?(challengeString: String) {
        self.inputString = challengeString
        
        guard attestService.isSupported == true else {
            print("[!] Attest service not available:")
            return nil
        }
    }
    
    func generateKey(completion: @escaping (String?)->()) {
        guard let id = userDefaults.object(forKey:keyName) as? String else {
            attestService.generateKey { keyIdentifier, error in
                guard error == nil, keyIdentifier != nil else {
                    completion(nil)
                    return
                }
                self.keyID = keyIdentifier
                if self.keyID != nil {
                    print("🐝 Generated key")
                    self.userDefaults.set(self.keyID, forKey: self.keyName)
                    completion(self.keyID)
                }
            }
            return
        }
        self.keyID = id
        completion(id)
    }
    
    func keyIdentifier() -> String {
        return ("\(self.keyID ?? "Error in Key ID")")
    }

    // https://developer.apple.com/documentation/devicecheck/dcappattestservice/3573911-attestkey
    // A SHA256 hash of a unique, single-use data block that embeds a challenge from your server.
    func preAttestation(completion: @escaping (Bool)->()) {
        
        let inputString = self.inputString
        let challenge = Data(inputString.utf8)
        let hash = Data(SHA256.hash(data: challenge))
        
        
        print("🐝 Calling Apple servers")
        attestService.attestKey(self.keyID!, clientDataHash: hash, completionHandler: { attestation, error in
            guard let attestationObject = attestation else {
                completion(false)
                return
            }
            self.attestationString = attestation?.base64EncodedString()
            let decodedData: Data? = Data(base64Encoded: attestationObject.base64EncodedData(), options: .ignoreUnknownCharacters)
            guard let finalDecodedData = decodedData else {
                completion(false)
                return
            }
            
            guard let decodedAttestation = String(data: finalDecodedData.base64EncodedData(), encoding: .utf8) else {
                completion(false)
                return
            }
            
            completion(true)
        })
    }
    
}
