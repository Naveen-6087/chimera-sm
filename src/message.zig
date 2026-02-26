const std = @import("std");
const chat_crypto = @import("chat_crypto.zig");

const Ed25519 = std.crypto.sign.Ed25519;

/// Wire-format message types.
pub const MessageType = enum(u8) {
    /// Initial key exchange: sender shares their public keys.
    key_exchange = 0x01,
    /// An encrypted + signed chat message.
    chat = 0x02,
    /// Acknowledgement of receipt.
    ack = 0x03,
};

/// A serializable key-exchange message.
pub const KeyExchangePayload = struct {
    dh_public: [chat_crypto.key_length]u8,
    sign_public: [Ed25519.PublicKey.encoded_length]u8,
    display_name: []const u8,

    pub fn serialize(self: *const KeyExchangePayload, allocator: std.mem.Allocator) ![]u8 {
        // Format: type(1) + dh_pub(32) + sign_pub(32) + name_len(2) + name
        const name_len: u16 = @intCast(self.display_name.len);
        const total = 1 + 32 + 32 + 2 + self.display_name.len;
        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);

        var offset: usize = 0;
        buf[offset] = @intFromEnum(MessageType.key_exchange);
        offset += 1;

        @memcpy(buf[offset .. offset + 32], &self.dh_public);
        offset += 32;

        @memcpy(buf[offset .. offset + 32], &self.sign_public);
        offset += 32;

        std.mem.writeInt(u16, buf[offset..][0..2], name_len, .big);
        offset += 2;

        @memcpy(buf[offset .. offset + self.display_name.len], self.display_name);

        return buf;
    }

    pub fn deserialize(data: []const u8) !KeyExchangePayload {
        if (data.len < 1 + 32 + 32 + 2) return error.MessageTooShort;
        if (data[0] != @intFromEnum(MessageType.key_exchange)) return error.WrongMessageType;

        var offset: usize = 1;
        const dh_public: [32]u8 = data[offset..][0..32].*;
        offset += 32;

        const sign_public: [32]u8 = data[offset..][0..32].*;
        offset += 32;

        const name_len = std.mem.readInt(u16, data[offset..][0..2], .big);
        offset += 2;

        if (data.len < offset + name_len) return error.MessageTooShort;
        const display_name = data[offset .. offset + name_len];

        return KeyExchangePayload{
            .dh_public = dh_public,
            .sign_public = sign_public,
            .display_name = display_name,
        };
    }
};

/// An encrypted chat message (wire format).
pub const ChatMessage = struct {
    /// Ed25519 signature over (timestamp ++ encrypted_body).
    signature: [chat_crypto.signature_length]u8,
    /// Unix timestamp (seconds).
    timestamp: i64,
    /// The encrypted payload (nonce + ciphertext + tag); plaintext is the UTF-8 message.
    encrypted_body: []const u8,

    pub fn serialize(self: *const ChatMessage, allocator: std.mem.Allocator) ![]u8 {
        // Format: type(1) + sig(64) + timestamp(8) + body_len(4) + body
        const body_len: u32 = @intCast(self.encrypted_body.len);
        const total = 1 + 64 + 8 + 4 + self.encrypted_body.len;
        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);

        var offset: usize = 0;
        buf[offset] = @intFromEnum(MessageType.chat);
        offset += 1;

        @memcpy(buf[offset .. offset + 64], &self.signature);
        offset += 64;

        std.mem.writeInt(i64, buf[offset..][0..8], self.timestamp, .big);
        offset += 8;

        std.mem.writeInt(u32, buf[offset..][0..4], body_len, .big);
        offset += 4;

        @memcpy(buf[offset .. offset + self.encrypted_body.len], self.encrypted_body);

        return buf;
    }

    pub fn deserialize(data: []const u8) !ChatMessage {
        if (data.len < 1 + 64 + 8 + 4) return error.MessageTooShort;
        if (data[0] != @intFromEnum(MessageType.chat)) return error.WrongMessageType;

        var offset: usize = 1;
        const signature: [64]u8 = data[offset..][0..64].*;
        offset += 64;

        const timestamp = std.mem.readInt(i64, data[offset..][0..8], .big);
        offset += 8;

        const body_len = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;

        if (data.len < offset + body_len) return error.MessageTooShort;
        const encrypted_body = data[offset .. offset + body_len];

        return ChatMessage{
            .signature = signature,
            .timestamp = timestamp,
            .encrypted_body = encrypted_body,
        };
    }

    /// Build the data that gets signed: timestamp ++ encrypted_body.
    pub fn signedPayload(self: *const ChatMessage, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 8 + self.encrypted_body.len);
        std.mem.writeInt(i64, buf[0..8], self.timestamp, .big);
        @memcpy(buf[8..], self.encrypted_body);
        return buf;
    }
};

// ─ Tests ──────────────────────────────────────────────────────────────

test "key exchange roundtrip" {
    const allocator = std.testing.allocator;

    const original = KeyExchangePayload{
        .dh_public = [_]u8{0xAA} ** 32,
        .sign_public = [_]u8{0xBB} ** 32,
        .display_name = "Alice",
    };

    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);

    const decoded = try KeyExchangePayload.deserialize(serialized);
    try std.testing.expectEqualSlices(u8, &original.dh_public, &decoded.dh_public);
    try std.testing.expectEqualSlices(u8, &original.sign_public, &decoded.sign_public);
    try std.testing.expectEqualStrings("Alice", decoded.display_name);
}

test "chat message roundtrip" {
    const allocator = std.testing.allocator;

    const original = ChatMessage{
        .signature = [_]u8{0xCC} ** 64,
        .timestamp = 1700000000,
        .encrypted_body = "encrypted payload data here",
    };

    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);

    const decoded = try ChatMessage.deserialize(serialized);
    try std.testing.expectEqualSlices(u8, &original.signature, &decoded.signature);
    try std.testing.expectEqual(original.timestamp, decoded.timestamp);
    try std.testing.expectEqualStrings("encrypted payload data here", decoded.encrypted_body);
}
