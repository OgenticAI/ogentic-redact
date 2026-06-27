/// OgenticRedact — Swift binding stub for the `ogentic-redact` Rust library.
///
/// The full Redactor API will be exposed here once the Rust core detection
/// logic lands (subsequent R* tickets). For F1 this file establishes the
/// Swift module boundary and exposes the version query only.
public enum OgenticRedact {
    /// The version of the underlying ogentic-redact-core library.
    public static var version: String {
        String(cString: ogentic_redact_version())
    }
}
