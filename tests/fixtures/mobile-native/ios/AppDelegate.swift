import UIKit
import Foundation
import CryptoKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private let label = "bpilot-mobilefixture-protocol-v1"
    func application(_ app: UIApplication,
                     didFinishLaunchingWithOptions opts: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = UIViewController()
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
    func application(_ app: UIApplication, open url: URL,
                     options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        guard url.scheme == "bpilottest", url.host == "probe",
              url.path == "/candidate" || url.path == "/control",
              let nonce = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "nonce" })?.value,
              nonce.count == 32,
              nonce.allSatisfy({ "0123456789abcdef".contains($0) }) else { return false }
        let phase = String(url.path.dropFirst())
        let files = FileManager.default
        do {
            let dir = try files.url(for: .documentDirectory, in: .userDomainMask,
                                    appropriateFor: nil, create: true)
            let marker = dir.appendingPathComponent("bpilot-local-marker")
            if files.fileExists(atPath: marker.path) { try files.removeItem(at: marker) }
            if phase == "candidate" { try Data(nonce.utf8).write(to: marker, options: .atomic) }
            let seen = (try? Data(contentsOf: marker)) == Data(nonce.utf8)
            let digest = SHA256.hash(data: Data(label.utf8))
                .map { String(format: "%02x", $0) }.joined()
            let result: [String: Any] = [
                "schema_version": 1,
                "phase": phase,
                "nonce": nonce,
                "fixture_package": "org.bountypilot.fixture",
                "fixture_build_sha256": digest,
                "sink_seen": seen
            ]
            let data = try JSONSerialization.data(withJSONObject: result)
            try data.write(to: dir.appendingPathComponent("bpilot-" + phase + ".json"),
                           options: .atomic)
            return true
        } catch { return false }
    }
}
