import Foundation

/// Why a character was shown escaped. The window names the classes next to
/// the value, so an escape is never mistaken for literal text.
public enum EscapeMark: String, CaseIterable, Sendable {
    case control
    case bidi
    case zeroWidth = "zero-width"
    case nonASCII = "non-ASCII"
}

/// One value as the window shows it: `shown` holds printable ASCII only.
/// '"' and '\' are escaped with a backslash, \n \r \t keep their short
/// form, and every other character outside U+0020..U+007E is written as
/// \u{XXXX} (at least four uppercase hex digits) with its class in `marks`.
public struct DisplayText: Equatable, Sendable {
    public let shown: String
    /// UTF-8 length of the original value.
    public let byteCount: Int
    public let marks: Set<EscapeMark>

    public init(_ s: String) {
        var out = ""
        var marks = Set<EscapeMark>()
        for r in s.unicodeScalars {
            let v = r.value
            switch v {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x20...0x7E: out.unicodeScalars.append(r)
            case 0x0A: out += "\\n"; marks.insert(.control)
            case 0x0D: out += "\\r"; marks.insert(.control)
            case 0x09: out += "\\t"; marks.insert(.control)
            default:
                out += "\\u{" + String(format: "%04X", v) + "}"
                marks.insert(Self.mark(of: v))
            }
        }
        shown = out
        byteCount = s.utf8.count
        self.marks = marks
    }

    init(number: String) {
        shown = number
        byteCount = number.utf8.count
        marks = []
    }

    /// `"shown"`, followed by the escape classes when there are any.
    public var quoted: String { "\"" + shown + "\"" + suffix }

    var suffix: String {
        marks.isEmpty ? "" : "  [escaped: " + EscapeMark.allCases.filter(marks.contains).map(\.rawValue).joined(separator: ", ") + "]"
    }

    static func mark(of v: UInt32) -> EscapeMark {
        switch v {
        case 0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029:
            return .control
        case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
            return .bidi
        case 0x00AD, 0x034F, 0x115F, 0x1160, 0x180E, 0x200B...0x200D, 0x2060...0x2064,
             0x3164, 0xFE00...0xFE0F, 0xFEFF, 0xFFA0, 0xE0000...0xE007F, 0xE0100...0xE01EF:
            return .zeroWidth
        default:
            return .nonASCII
        }
    }
}

/// A named payload field, one line in the window.
public struct DisplayField: Equatable, Sendable {
    public let name: String
    public let text: DisplayText
    let isString: Bool
    let note: String?

    /// `name "value"` for strings, `name 123` for numbers, with an optional
    /// human note such as the UTC form of a timestamp.
    public var line: String {
        var s = name + " " + (isString ? text.quoted : text.shown)
        if let note { s += " (" + note + ")" }
        return s
    }
}

/// One argv or env entry: its index, its length and its escaped value.
public struct DisplayEntry: Equatable, Sendable {
    public let list: String
    public let index: Int
    public let text: DisplayText

    /// `argv[3] 4 bytes "ls -l"  [escaped: ...]`
    public var line: String { "\(list)[\(index)] \(text.byteCount) bytes \(text.quoted)" }
}

/// Size limits past which the signer refuses instead of showing a value
/// it cannot show whole (ADR 0006, V7). Long values are shown in full with
/// scrolling up to these limits, never truncated.
public struct DisplayLimits: Sendable, Equatable {
    /// Longest `shown` text of one value, escapes included.
    public var maxShownLength: Int
    /// Most entries in argv and in env.
    public var maxEntries: Int

    public init(maxShownLength: Int = 64 * 1024, maxEntries: Int = 1024) {
        self.maxShownLength = maxShownLength
        self.maxEntries = maxEntries
    }

    public static let standard = DisplayLimits()
}

public enum DisplayError: Error, Equatable {
    /// The named field (`argv[2]`, `env`, `cwd`, ...) cannot be shown whole.
    case undisplayable(field: String)
}

/// What the signer window shows for one queue item, built only from the
/// parsed payload (never from the QueueItem display copies): the short code,
/// every scalar field, then argv and env one entry per line.
public struct ApprovalDisplay: Sendable {
    public let shortCode: String
    public let hostID: DisplayText
    public let fields: [DisplayField]
    public let argv: [DisplayEntry]
    public let env: [DisplayEntry]

    public init(payload p: ApprovalPayload, raw: Data, limits: DisplayLimits = .standard) throws {
        func check(_ name: String, _ t: DisplayText) throws -> DisplayText {
            guard t.shown.utf8.count <= limits.maxShownLength else { throw DisplayError.undisplayable(field: name) }
            return t
        }
        func str(_ name: String, _ v: String) throws -> DisplayField {
            DisplayField(name: name, text: try check(name, DisplayText(v)), isString: true, note: nil)
        }
        func num(_ name: String, _ v: String, note: String? = nil) -> DisplayField {
            DisplayField(name: name, text: DisplayText(number: v), isString: false, note: note)
        }
        func entries(_ list: String, _ vs: [String]) throws -> [DisplayEntry] {
            guard vs.count <= limits.maxEntries else { throw DisplayError.undisplayable(field: list) }
            return try vs.enumerated().map { i, v in
                DisplayEntry(list: list, index: i, text: try check("\(list)[\(i)]", DisplayText(v)))
            }
        }
        shortCode = ApprovalPayload.shortCode(of: raw)
        hostID = DisplayText(p.hostID)
        fields = [
            try str("host_id", p.hostID),
            try str("host_key", p.hostKey),
            try str("item_id", p.itemID),
            try str("request_hash", p.requestHash),
            try str("challenge", p.challenge),
            try str("requester", p.requester),
            num("uid", String(p.uid)),
            try str("user", p.user),
            try str("executable", p.executable),
            num("exe_dev", String(p.exeDev)),
            num("exe_ino", String(p.exeIno)),
            try str("cwd", p.cwd),
            try str("nonce", p.nonce),
            num("queued_at", String(p.queuedAt), note: Self.utc(p.queuedAt)),
            num("deadline", String(p.deadline), note: Self.utc(p.deadline)),
            num("token_ttl_seconds", String(p.tokenTTLSeconds)),
        ]
        argv = try entries("argv", p.argv)
        env = try entries("env", p.env)
    }

    /// UTC ISO 8601 with milliseconds. Formatting only: the Mac clock takes
    /// no part in any check (ADR 0006, V6).
    static func utc(_ ms: Int64) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
    }
}
