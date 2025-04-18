//
//  CoD_EXApp.swift
//  CoD-EX
//
//  Created by Dakshinamurthy Balusamuy on 17/04/25.
//

import SwiftUI

@main
struct CoD_EXApp: App {
    let persistenceController = PersistenceController.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.managedObjectContext, persistenceController.container.viewContext)
        }
    }
}
