const std = @import("std");
const chat_crypto = @import("chat_crypto.zig");
const message = @import("message.zig");
const storage = @import("storage.zig");

const Ed25519 = std.crypto.sign.Ed25519;

/// Represents an active chat session between two users.
pub const ChatSession = struct {
    allocator: std.mem.Allocator,
    /// Our identity (keypairs).
    identity: chat_crypto.Identity,
    /// Our display name.
    display_name: []const u8,
    /// Peer's public info (set after key exchange).
    peer: ?chat_crypto.PeerPublicInfo,
    /// Peer's display name.
    peer_name: ?[]const u8,
    /// Derived shared encryption key (set after key exchange).
    shared_key: ?[chat_crypto.key_length]u8,
    /// Chat history (decrypted messages for display).
    history: std.ArrayList(HistoryEntry),
    /// Optional persistent storage.
    store: ?storage.ChatStorage,

    pub const HistoryEntry = struct {
        sender: []const u8,
        text: []const u8,
        timestamp: i64,
        verified: bool,
    };

    /// Create a new chat session.
    pub fn init(allocator: std.mem.Allocator, display_name: []const u8, history_path: ?[]const u8) !ChatSession {
        const id = chat_crypto.Identity.generate();
        const store = if (history_path) |path|
            try storage.ChatStorage.init(allocator, path)
        else
            null;

        return ChatSession{
            .allocator = allocator,
            .identity = id,
            .display_name = display_name,
            .peer = null,
            .peer_name = null,
            .shared_key = null,
            .history = .{},
            .store = store,
        };
    }

    pub fn deinit(self: *ChatSession) void {
        // Free history entries
        for (self.history.items) |entry| {
            self.allocator.free(entry.text);
        }
        self.history.deinit(self.allocator);

        if (self.store) |*s| {
            s.deinit();
        }

        // Zero out secret keys
        std.crypto.secureZero(u8, &self.identity.dh_secret);
        if (self.shared_key) |*k| {
            std.crypto.secureZero(u8, k);
        }
    }

    /// Generate our key-exchange payload to send to the peer.
    pub fn createKeyExchange(self: *const ChatSession) !message.KeyExchangePayload {
        return message.KeyExchangePayload{
            .dh_public = self.identity.dh_public,
            .sign_public = self.identity.signingPublicKey(),
            .display_name = self.display_name,
        };
    }

    /// Process an incoming key-exchange message from a peer.
    pub fn processKeyExchange(self: *ChatSession, payload: message.KeyExchangePayload) !void {
        self.peer = chat_crypto.PeerPublicInfo{
            .dh_public = payload.dh_public,
            .sign_public = payload.sign_public,
        };
        // Save peer name (points into deserialized data, so we duplicate it)
        self.peer_name = try self.allocator.dupe(u8, payload.display_name);

        // Derive shared key
        self.shared_key = try chat_crypto.deriveSharedKey(
            self.identity.dh_secret,
            payload.dh_public,
        );
    }

    /// Encrypt, sign, and package a plaintext message for sending.
    pub fn prepareMessage(self: *ChatSession, plaintext: []const u8) ![]u8 {
        const shared_key = self.shared_key orelse return error.NoSharedKey;

        // Encrypt the message
        const encrypted = try chat_crypto.encrypt(self.allocator, plaintext, shared_key);
        defer self.allocator.free(encrypted);

        // Build the chat message
        const timestamp = std.time.timestamp();
        var msg = message.ChatMessage{
            .signature = undefined,
            .timestamp = timestamp,
            .encrypted_body = encrypted,
        };

        // Sign (timestamp ++ encrypted_body)
        const signed_data = try msg.signedPayload(self.allocator);
        defer self.allocator.free(signed_data);
        msg.signature = try chat_crypto.sign(signed_data, self.identity.sign_keypair);

        // Add to local history
        const text_copy = try self.allocator.dupe(u8, plaintext);
        try self.history.append(self.allocator, HistoryEntry{
            .sender = self.display_name,
            .text = text_copy,
            .timestamp = timestamp,
            .verified = true,
        });

        // Persist if storage is available
        if (self.store) |*s| {
            try s.appendEntry(self.display_name, plaintext, timestamp, shared_key);
        }

        // Serialize for wire
        const wire = try msg.serialize(self.allocator);
        return wire;
    }

    /// Receive, verify, and decrypt an incoming chat message.
    pub fn receiveMessage(self: *ChatSession, data: []const u8) ![]const u8 {
        const shared_key = self.shared_key orelse return error.NoSharedKey;
        const peer = self.peer orelse return error.NoPeer;

        const msg = try message.ChatMessage.deserialize(data);

        // Verify signature
        const signed_data = try msg.signedPayload(self.allocator);
        defer self.allocator.free(signed_data);
        chat_crypto.verify(signed_data, msg.signature, peer.sign_public) catch
            return error.SignatureVerificationFailed;

        // Decrypt
        const plaintext = try chat_crypto.decrypt(self.allocator, msg.encrypted_body, shared_key);

        // Add to history
        const text_copy = try self.allocator.dupe(u8, plaintext);
        const sender_name = self.peer_name orelse "peer";
        try self.history.append(self.allocator, HistoryEntry{
            .sender = sender_name,
            .text = text_copy,
            .timestamp = msg.timestamp,
            .verified = true,
        });

        // Persist if storage is available
        if (self.store) |*s| {
            try s.appendEntry(sender_name, plaintext, msg.timestamp, shared_key);
        }

        return plaintext;
    }

    /// Print chat history using debug.print.
    pub fn printHistory(self: *const ChatSession) void {
        for (self.history.items) |entry| {
            const verified_str: []const u8 = if (entry.verified) " verified" else " UNVERIFIED";
            std.debug.print("[{d}] {s}{s}: {s}\n", .{
                entry.timestamp,
                entry.sender,
                verified_str,
                entry.text,
            });
        }
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "full session: key exchange + encrypt + decrypt" {
    const allocator = std.testing.allocator;

    var alice = try ChatSession.init(allocator, "Alice", null);
    defer alice.deinit();

    var bob = try ChatSession.init(allocator, "Bob", null);
    defer bob.deinit();

    // Exchange keys
    const alice_kx = try alice.createKeyExchange();
    const bob_kx = try bob.createKeyExchange();

    // Serialize and deserialize key exchange (simulating network)
    const alice_kx_data = try alice_kx.serialize(allocator);
    defer allocator.free(alice_kx_data);
    const bob_kx_data = try bob_kx.serialize(allocator);
    defer allocator.free(bob_kx_data);

    const alice_kx_received = try message.KeyExchangePayload.deserialize(bob_kx_data);
    const bob_kx_received = try message.KeyExchangePayload.deserialize(alice_kx_data);

    try bob.processKeyExchange(bob_kx_received);
    defer allocator.free(bob.peer_name.?);
    try alice.processKeyExchange(alice_kx_received);
    defer allocator.free(alice.peer_name.?);

    // Alice sends a message
    const wire_msg = try alice.prepareMessage("Hello Bob, this is encrypted!");
    defer allocator.free(wire_msg);

    // Bob receives and decrypts
    const plaintext = try bob.receiveMessage(wire_msg);
    defer allocator.free(plaintext);

    try std.testing.expectEqualStrings("Hello Bob, this is encrypted!", plaintext);

    // Both should have 1 history entry
    try std.testing.expectEqual(@as(usize, 1), alice.history.items.len);
    try std.testing.expectEqual(@as(usize, 1), bob.history.items.len);
}
