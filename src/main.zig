const std = @import("std");
const chat_crypto = @import("chat_crypto.zig");
const message = @import("message.zig");
const session = @import("session.zig");
const storage = @import("storage.zig");

const ChatSession = session.ChatSession;
const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print(
        \\
        \\========================================================
        \\         Zig Encrypted Chat - Demo Mode
        \\
        \\  Cryptographic primitives used:
        \\  - X25519 Diffie-Hellman key exchange
        \\  - HKDF-SHA256 key derivation
        \\  - ChaCha20-Poly1305 AEAD encryption
        \\  - Ed25519 digital signatures
        \\  - Encrypted on-disk chat history
        \\========================================================
        \\
        \\
    , .{});

    // -- Demo: simulate a full conversation between Alice and Bob --

    print("-- Step 1: Generating identities --\n\n", .{});

    var alice = try ChatSession.init(allocator, "Alice", "alice_history.bin");
    defer alice.deinit();
    print("  Alice's DH public key:   {x}\n", .{alice.identity.dh_public});
    print("  Alice's Sign public key: {x}\n\n", .{alice.identity.signingPublicKey()});

    var bob = try ChatSession.init(allocator, "Bob", "bob_history.bin");
    defer bob.deinit();
    print("  Bob's DH public key:     {x}\n", .{bob.identity.dh_public});
    print("  Bob's Sign public key:   {x}\n\n", .{bob.identity.signingPublicKey()});

    // -- Key Exchange --
    print("-- Step 2: Key Exchange (X25519 + HKDF) --\n\n", .{});

    const alice_kx = try alice.createKeyExchange();
    const bob_kx = try bob.createKeyExchange();

    // Serialize for "network" transfer
    const alice_kx_wire = try alice_kx.serialize(allocator);
    defer allocator.free(alice_kx_wire);
    const bob_kx_wire = try bob_kx.serialize(allocator);
    defer allocator.free(bob_kx_wire);

    print("  Alice key-exchange packet: {d} bytes\n", .{alice_kx_wire.len});
    print("  Bob key-exchange packet:   {d} bytes\n", .{bob_kx_wire.len});

    // Each side receives the other's key-exchange
    const alice_rx_kx = try message.KeyExchangePayload.deserialize(bob_kx_wire);
    const bob_rx_kx = try message.KeyExchangePayload.deserialize(alice_kx_wire);

    try alice.processKeyExchange(alice_rx_kx);
    defer allocator.free(alice.peer_name.?);
    try bob.processKeyExchange(bob_rx_kx);
    defer allocator.free(bob.peer_name.?);

    print("  Shared key derived:        {x}\n", .{alice.shared_key.?});
    print("  Keys match:                {}\n\n", .{std.mem.eql(u8, &alice.shared_key.?, &bob.shared_key.?)});

    // -- Encrypted Messages --
    print("-- Step 3: Encrypted + Signed Messages --\n\n", .{});

    const conversations = [_]struct { sender: []const u8, text: []const u8 }{
        .{ .sender = "alice", .text = "Hey Bob! This message is encrypted with ChaCha20-Poly1305." },
        .{ .sender = "bob", .text = "Hi Alice! And signed with Ed25519 too!" },
        .{ .sender = "alice", .text = "Nobody can read or tamper with our messages." },
        .{ .sender = "bob", .text = "Even if they intercept the traffic, they can't decrypt without our shared key." },
    };

    for (conversations) |m| {
        if (std.mem.eql(u8, m.sender, "alice")) {
            const wire = try alice.prepareMessage(m.text);
            defer allocator.free(wire);

            print("  Alice -> [{d} bytes encrypted] -> Bob\n", .{wire.len});

            const decrypted = try bob.receiveMessage(wire);
            defer allocator.free(decrypted);

            print("  Bob decrypted: \"{s}\"\n\n", .{decrypted});
        } else {
            const wire = try bob.prepareMessage(m.text);
            defer allocator.free(wire);

            print("  Bob -> [{d} bytes encrypted] -> Alice\n", .{wire.len});

            const decrypted = try alice.receiveMessage(wire);
            defer allocator.free(decrypted);

            print("  Alice decrypted: \"{s}\"\n\n", .{decrypted});
        }
    }

    // -- Tamper detection --
    print("-- Step 4: Tamper Detection Demo --\n\n", .{});

    const legit_wire = try alice.prepareMessage("This is a legit message");
    defer allocator.free(legit_wire);

    // Tamper with a byte in the encrypted body
    var tampered = try allocator.dupe(u8, legit_wire);
    defer allocator.free(tampered);
    if (tampered.len > 80) {
        tampered[80] ^= 0xFF; // Flip a byte
    }

    if (bob.receiveMessage(tampered)) |plaintext| {
        allocator.free(plaintext);
        print("  Tampered message was accepted (unexpected!)\n", .{});
    } else |err| {
        print("  Tampered message rejected: {}\n", .{err});
        print("  Integrity check works!\n\n", .{});
    }

    // -- Chat History --
    print("-- Step 5: Encrypted Chat History --\n\n", .{});

    print("  Alice's conversation ({d} messages):\n", .{alice.history.items.len});
    for (alice.history.items) |entry| {
        const checkmark: []const u8 = if (entry.verified) "[verified]" else "[UNVERIFIED]";
        print("    {s} {s}: {s}\n", .{ checkmark, entry.sender, entry.text });
    }

    print("\n", .{});

    // Read back from disk
    if (alice.store) |*s| {
        var disk_entries = try s.readAll(alice.shared_key.?);
        defer {
            for (disk_entries.items) |*e| {
                e.deinit(allocator);
            }
            disk_entries.deinit(allocator);
        }

        print("  On-disk history ({d} entries, encrypted with ChaCha20-Poly1305):\n", .{disk_entries.items.len});
        for (disk_entries.items) |entry| {
            print("    {s}: {s}\n", .{ entry.sender, entry.text });
        }
    }

    print(
        \\
        \\-- Done! --
        \\
        \\All messages were:
        \\  - Encrypted with ChaCha20-Poly1305 (authenticated encryption)
        \\  - Signed with Ed25519 (digital signatures)
        \\  - Key exchange via X25519 Diffie-Hellman
        \\  - Keys derived with HKDF-SHA256
        \\  - Chat history stored encrypted on disk
        \\
        \\
    , .{});

    // Clean up demo files
    std.fs.cwd().deleteFile("alice_history.bin") catch {};
    std.fs.cwd().deleteFile("bob_history.bin") catch {};
}

// Pull in all module tests
test {
    _ = chat_crypto;
    _ = message;
    _ = session;
    _ = storage;
}
