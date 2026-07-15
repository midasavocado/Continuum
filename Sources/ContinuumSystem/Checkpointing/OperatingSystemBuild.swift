import ContinuumCore
import Darwin

func currentOperatingSystemBuild() throws -> String {
    var length = 0
    guard sysctlbyname("kern.osversion", nil, &length, nil, 0) == 0,
          length > 1 else {
        throw ContinuumError.integrityFailure(
            "Continuum could not read this Mac's operating-system build identifier."
        )
    }

    var bytes = [CChar](repeating: 0, count: length)
    guard sysctlbyname("kern.osversion", &bytes, &length, nil, 0) == 0 else {
        throw ContinuumError.integrityFailure(
            "Continuum could not read this Mac's operating-system build identifier."
        )
    }
    let terminator = bytes.firstIndex(of: 0) ?? bytes.endIndex
    return String(decoding: bytes[..<terminator].map(UInt8.init(bitPattern:)), as: UTF8.self)
}
