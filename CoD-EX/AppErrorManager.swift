import Foundation
import SwiftUI

class AppErrorManager: ObservableObject {
    @Published var errorMessage: String? = nil
    @Published var showError: Bool = false

    func present(_ message: String) {
        errorMessage = message
        showError = true
    }
} 