const std = @import("std");
const crypto = std.crypto;

const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

pub const key_length = 32;
pub const nonce_length = ChaCha20Poly1305.nonce_length; // 12
pub const tag_length = ChaCha20Poly1305.tag_length; // 16
pub const signature_length = Ed25519.Signature.encoded_length; // 64

/// A user's full identity: X25519 for key exchange + Ed25519 for signing.
pub const Identity = struct {
    /// X25519 secret key (for Diffie-Hellman)
    dh_secret: [key_length]u8,
    /// X25519 public key (shared with peers)
    dh_public: [key_length]u8,
    /// Ed25519 signing keypair
    sign_keypair: Ed25519.KeyPair,

    /// Generate a new random identity.
    pub fn generate() Identity {
        const dh_kp = X25519.KeyPair.generate();
        const sign_kp = Ed25519.KeyPair.generate();

        return Identity{
            .dh_secret = dh_kp.secret_key,
            .dh_public = dh_kp.public_key,
            .sign_keypair = sign_kp,
        };
    }

    /// Get the public signing key (to share with peers for verification).
    pub fn signingPublicKey(self: *const Identity) [Ed25519.PublicKey.encoded_length]u8 {
        return self.sign_keypair.public_key.bytes;
    }
};

/// Public info about a peer (what they share with us).
pub const PeerPublicInfo = struct {
    dh_public: [key_length]u8,
    sign_public: [Ed25519.PublicKey.encoded_length]u8,
};

/// Derives a symmetric encryption key from a shared DH secret using HKDF.
pub fn deriveSharedKey(
    our_secret: [key_length]u8,
    their_public: [key_length]u8,
) ![key_length]u8 {
    const shared_secret = try X25519.scalarmult(our_secret, their_public);

    // Use HKDF to derive a proper encryption key from the raw shared secret
    const salt = [_]u8{0} ** HkdfSha256.prk_length;
    const prk = HkdfSha256.extract(&salt, &shared_secret);
    var derived_key: [key_length]u8 = undefined;
    HkdfSha256.expand(&derived_key, "zig-chat-v1-encryption-key", prk);
    return derived_key;
}

/// Encrypt a plaintext message using ChaCha20-Poly1305.
/// Returns: nonce ++ ciphertext ++ tag (all concatenated).
pub fn encrypt(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    shared_key: [key_length]u8,
) ![]u8 {
    // Generate random nonce
    var nonce: [nonce_length]u8 = undefined;
    crypto.random.bytes(&nonce);

    // Allocate output: nonce + ciphertext + tag
    const out = try allocator.alloc(u8, nonce_length + plaintext.len + tag_length);
    errdefer allocator.free(out);

    // Copy nonce to the front
    @memcpy(out[0..nonce_length], &nonce);

    // Encrypt in-place into the output buffer
    var tag: [tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(
        out[nonce_length .. nonce_length + plaintext.len],
        &tag,
        plaintext,
        "",
        nonce,
        shared_key,
    );

    // Append tag
    @memcpy(out[nonce_length + plaintext.len ..], &tag);

    return out;
}

/// Decrypt a message encrypted with `encrypt`.
/// Input format: nonce (12) ++ ciphertext ++ tag (16).
pub fn decrypt(
    allocator: std.mem.Allocator,
    encrypted: []const u8,
    shared_key: [key_length]u8,
) ![]u8 {
    if (encrypted.len < nonce_length + tag_length) {
        return error.MessageTooShort;
    }

    const nonce: [nonce_length]u8 = encrypted[0..nonce_length].*;
    const ciphertext_len = encrypted.len - nonce_length - tag_length;
    const ciphertext = encrypted[nonce_length .. nonce_length + ciphertext_len];
    const tag: [tag_length]u8 = encrypted[nonce_length + ciphertext_len ..][0..tag_length].*;

    const plaintext = try allocator.alloc(u8, ciphertext_len);
    errdefer allocator.free(plaintext);

    ChaCha20Poly1305.decrypt(
        plaintext,
        ciphertext,
        tag,
        "",
        nonce,
        shared_key,
    ) catch return error.DecryptionFailed;

    return plaintext;
}

/// Sign a message with Ed25519.
pub fn sign(message: []const u8, keypair: Ed25519.KeyPair) ![signature_length]u8 {
    const sig = try keypair.sign(message, null);
    return sig.toBytes();
}

/// Verify an Ed25519 signature.
pub fn verify(
    message: []const u8,
    sig_bytes: [signature_length]u8,
    public_key_bytes: [Ed25519.PublicKey.encoded_length]u8,
) !void {
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    const public_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
    sig.verify(message, public_key) catch return error.InvalidSignature;
}

test "identity generation" {
    const id = Identity.generate();
    // Public keys should not be all zeros
    const zero = [_]u8{0} ** key_length;
    try std.testing.expect(!std.mem.eql(u8, &id.dh_public, &zero));
}

test "key exchange symmetry" {
    const alice = Identity.generate();
    const bob = Identity.generate();

    const alice_shared = try deriveSharedKey(alice.dh_secret, bob.dh_public);
    const bob_shared = try deriveSharedKey(bob.dh_secret, alice.dh_public);

    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "encrypt and decrypt roundtrip" {
    const alice = Identity.generate();
    const bob = Identity.generate();
    const shared_key = try deriveSharedKey(alice.dh_secret, bob.dh_public);

    const allocator = std.testing.allocator;
    const message = "Hello, encrypted world!";

    const encrypted = try encrypt(allocator, message, shared_key);
    defer allocator.free(encrypted);

    const decrypted = try decrypt(allocator, encrypted, shared_key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(message, decrypted);
}

test "decrypt with wrong key fails" {
    const alice = Identity.generate();
    const bob = Identity.generate();
    const eve = Identity.generate();

    const real_key = try deriveSharedKey(alice.dh_secret, bob.dh_public);
    const wrong_key = try deriveSharedKey(eve.dh_secret, bob.dh_public);

    const allocator = std.testing.allocator;
    const encrypted = try encrypt(allocator, "secret", real_key);
    defer allocator.free(encrypted);

    const result = decrypt(allocator, encrypted, wrong_key);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "sign and verify" {
    const alice = Identity.generate();
    const message_text = "I approve this message";

    const sig = try sign(message_text, alice.sign_keypair);
    try verify(message_text, sig, alice.signingPublicKey());
}

test "verify with wrong key fails" {
    const alice = Identity.generate();
    const bob = Identity.generate();

    const sig = try sign("hello", alice.sign_keypair);
    const result = verify("hello", sig, bob.signingPublicKey());
    try std.testing.expectError(error.InvalidSignature, result);
}

test "verify tampered message fails" {
    const alice = Identity.generate();
    const sig = try sign("original", alice.sign_keypair);
    const result = verify("tampered", sig, alice.signingPublicKey());
    try std.testing.expectError(error.InvalidSignature, result);
}
