/// A JSON value as the payload reader needs it: numbers stay as their text,
/// so the field decoder decides what forms it accepts.
enum JSONValue {
    case string(String)
    case number(String)
    case array([JSONValue])
    case object([(String, JSONValue)])
    case bool(Bool)
    case null
}

/// A strict RFC 8259 reader over bytes. It refuses invalid UTF-8 (overlong
/// forms, surrogates, out of range), raw control bytes in strings and lone
/// surrogate escapes; it accepts other valid JSON (whitespace, any escape)
/// because the canonical re-encoding check refuses those afterwards. The
/// verdict is what counts: a payload Go refuses, this side refuses too.
struct JSONReader {
    private let b: [UInt8]
    private var i = 0
    private var depth = 0

    init(_ bytes: [UInt8]) { b = bytes }

    /// Reads exactly one object and nothing but whitespace after it.
    mutating func readDocumentObject() throws -> [(String, JSONValue)] {
        skipWS()
        guard case .object(let members) = try value() else { throw PayloadError("not an object") }
        skipWS()
        guard i == b.count else { throw PayloadError("trailing data") }
        return members
    }

    private mutating func skipWS() {
        while i < b.count, [0x20, 0x09, 0x0A, 0x0D].contains(b[i]) { i += 1 }
    }

    private mutating func expect(_ c: UInt8) throws {
        guard i < b.count, b[i] == c else { throw PayloadError("malformed JSON at byte \(i)") }
        i += 1
    }

    private mutating func value() throws -> JSONValue {
        guard i < b.count else { throw PayloadError("unexpected end") }
        switch b[i] {
        case 0x7B: return try object()
        case 0x5B: return try array()
        case 0x22: return .string(try string())
        case 0x74: try literal("true"); return .bool(true)
        case 0x66: try literal("false"); return .bool(false)
        case 0x6E: try literal("null"); return .null
        case 0x2D, 0x30...0x39: return .number(try number())
        default: throw PayloadError("malformed JSON at byte \(i)")
        }
    }

    private mutating func literal(_ s: String) throws {
        for c in s.utf8 { try expect(c) }
    }

    private mutating func nest() throws {
        depth += 1
        if depth > 32 { throw PayloadError("too deeply nested") }
    }

    private mutating func object() throws -> JSONValue {
        try nest(); defer { depth -= 1 }
        try expect(0x7B)
        var members: [(String, JSONValue)] = []
        skipWS()
        if i < b.count, b[i] == 0x7D { i += 1; return .object(members) }
        while true {
            skipWS()
            guard i < b.count, b[i] == 0x22 else { throw PayloadError("malformed JSON at byte \(i)") }
            let k = try string()
            skipWS()
            try expect(0x3A)
            skipWS()
            members.append((k, try value()))
            skipWS()
            guard i < b.count else { throw PayloadError("unexpected end") }
            if b[i] == 0x2C { i += 1; continue }
            try expect(0x7D)
            return .object(members)
        }
    }

    private mutating func array() throws -> JSONValue {
        try nest(); defer { depth -= 1 }
        try expect(0x5B)
        var items: [JSONValue] = []
        skipWS()
        if i < b.count, b[i] == 0x5D { i += 1; return .array(items) }
        while true {
            skipWS()
            items.append(try value())
            skipWS()
            guard i < b.count else { throw PayloadError("unexpected end") }
            if b[i] == 0x2C { i += 1; continue }
            try expect(0x5D)
            return .array(items)
        }
    }

    private mutating func number() throws -> String {
        let start = i
        if b[i] == 0x2D { i += 1 }
        func digits() -> Int {
            let s = i
            while i < b.count, b[i] >= 0x30, b[i] <= 0x39 { i += 1 }
            return i - s
        }
        guard i < b.count else { throw PayloadError("malformed number") }
        if b[i] == 0x30 { i += 1 } else if digits() == 0 { throw PayloadError("malformed number") }
        if i < b.count, b[i] == 0x2E {
            i += 1
            guard digits() > 0 else { throw PayloadError("malformed number") }
        }
        if i < b.count, b[i] == 0x65 || b[i] == 0x45 {
            i += 1
            if i < b.count, b[i] == 0x2B || b[i] == 0x2D { i += 1 }
            guard digits() > 0 else { throw PayloadError("malformed number") }
        }
        return String(decoding: b[start..<i], as: UTF8.self)
    }

    private mutating func hex4() throws -> UInt32 {
        guard i + 4 <= b.count else { throw PayloadError("short \\u escape") }
        var v: UInt32 = 0
        for _ in 0..<4 {
            let c = b[i]
            let d: UInt32
            switch c {
            case 0x30...0x39: d = UInt32(c - 0x30)
            case 0x61...0x66: d = UInt32(c - 0x61 + 10)
            case 0x41...0x46: d = UInt32(c - 0x41 + 10)
            default: throw PayloadError("bad \\u escape")
            }
            v = v << 4 | d
            i += 1
        }
        return v
    }

    private mutating func string() throws -> String {
        try expect(0x22)
        var out = String.UnicodeScalarView()
        while true {
            guard i < b.count else { throw PayloadError("unterminated string") }
            let c = b[i]
            switch c {
            case 0x22:
                i += 1
                return String(out)
            case 0x5C:
                i += 1
                guard i < b.count else { throw PayloadError("unterminated escape") }
                let e = b[i]
                i += 1
                switch e {
                case 0x22: out.append("\"")
                case 0x5C: out.append("\\")
                case 0x2F: out.append("/")
                case 0x62: out.append("\u{8}")
                case 0x66: out.append("\u{C}")
                case 0x6E: out.append("\n")
                case 0x72: out.append("\r")
                case 0x74: out.append("\t")
                case 0x75:
                    var v = try hex4()
                    if (0xD800...0xDBFF).contains(v) {
                        guard i + 2 <= b.count, b[i] == 0x5C, b[i + 1] == 0x75 else { throw PayloadError("lone surrogate") }
                        i += 2
                        let lo = try hex4()
                        guard (0xDC00...0xDFFF).contains(lo) else { throw PayloadError("lone surrogate") }
                        v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00)
                    }
                    guard let s = Unicode.Scalar(v) else { throw PayloadError("lone surrogate") }
                    out.append(s)
                default:
                    throw PayloadError("bad escape")
                }
            case 0x00..<0x20:
                throw PayloadError("raw control byte in a string")
            default:
                out.append(try utf8Scalar())
            }
        }
    }

    /// Decodes one strictly valid UTF-8 sequence.
    private mutating func utf8Scalar() throws -> Unicode.Scalar {
        let c0 = b[i]
        let bad = PayloadError("invalid UTF-8")
        let n: Int
        var v: UInt32
        var lo: UInt8 = 0x80
        var hi: UInt8 = 0xBF
        switch c0 {
        case 0x00...0x7F: i += 1; return Unicode.Scalar(c0)
        case 0xC2...0xDF: n = 1; v = UInt32(c0 & 0x1F)
        case 0xE0: n = 2; v = UInt32(c0 & 0x0F); lo = 0xA0
        case 0xE1...0xEC, 0xEE...0xEF: n = 2; v = UInt32(c0 & 0x0F)
        case 0xED: n = 2; v = UInt32(c0 & 0x0F); hi = 0x9F
        case 0xF0: n = 3; v = UInt32(c0 & 0x07); lo = 0x90
        case 0xF1...0xF3: n = 3; v = UInt32(c0 & 0x07)
        case 0xF4: n = 3; v = UInt32(c0 & 0x07); hi = 0x8F
        default: throw bad
        }
        guard i + n < b.count else { throw bad }
        for k in 1...n {
            let c = b[i + k]
            let (l, h) = k == 1 ? (lo, hi) : (UInt8(0x80), UInt8(0xBF))
            guard c >= l, c <= h else { throw bad }
            v = v << 6 | UInt32(c & 0x3F)
        }
        i += n + 1
        guard let s = Unicode.Scalar(v) else { throw bad }
        return s
    }
}
