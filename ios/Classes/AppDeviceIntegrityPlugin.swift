import Flutter
import UIKit

@available(iOS 14.0, *)
public class AppDeviceIntegrityPlugin: NSObject, FlutterPlugin {
public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "app_attestation", binaryMessenger: registrar.messenger())
    let instance = AppDeviceIntegrityPlugin()
      registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
      switch call.method {

      case "getAttestationServiceSupport":
          guard let args = call.arguments else {
              result(FlutterError(code: "-1", message: "iOS could not extract " +
                                  "flutter arguments in method: (getAttestationServiceSupport)", details: nil))
              return
          }

          guard let myArgs = args as? [String: Any] else {
              result(FlutterError(code: "-1", message: "iOS could not extract " +
                                  "flutter arguments in method: (getAttestationServiceSupport)", details: nil))
              return
          }

          guard let challengeString = myArgs["challengeString"] as? String else {
              result(FlutterError(code: "-1", message: "iOS could not extract " +
                                  "flutter arguments in method: (getAttestationServiceSupport)", details: nil))
              return
          }

          guard let attest = AppDeviceIntegrity(challengeString: challengeString) else {
              result(FlutterError(code: "-1", message: "iOS could not extract " +
                                  "flutter arguments in method: (getAttestationServiceSupport)", details: nil))
              return
          }
          
          attest.generateKey { key in
              print(attest.keyIdentifier())
              
              attest.preAttestation { success in
                  
                  if (success) {
                      var attestation = [String : String] ()
                      attestation["attestationString"] = attest.attestationString
                      attestation["keyID"] = attest.keyIdentifier()

                      let encoder = JSONEncoder()
                      if let json = try? encoder.encode(attestation) {
                          result(String(data: json, encoding: .utf8)!)
                      }
                  } else {
                      result(FlutterError(code: "-1", message: "iOS could not extract " +
                                          "flutter arguments in method: (getAttestationServiceSupport)", details: nil))
                      return
                  }
              }
          }
          
    default:
      result(FlutterMethodNotImplemented)

    }
  }
}
