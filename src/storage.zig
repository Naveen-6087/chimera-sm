const std = @import("std");
const chat_crypto = @import("chat_crypto.zig");

/// Stores encrypted chat history to disk.
/// Each entry is: entry_len(4) + encrypted_entry
/// Where encrypted_entry decrypts to: timestamp(8) + name_len(2) + name + message
pub const ChatStorage = struct {
    allocator: std.mem.Allocator,
    file_path: []const u8,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !ChatStorage {
        return ChatStorage{
            .allocator = allocator,
            .file_path = try allocator.dupe(u8, file_path),
        };
    }

    pub fn deinit(self: *ChatStorage) void {
        self.allocator.free(self.file_path);
    }

    /// Append a single chat entry (encrypted) to the history file.
    pub fn appendEntry(
        self: *ChatStorage,
        sender: []const u8,
        text: []const u8,
        timestamp: i64,
        encryption_key: [chat_crypto.key_length]u8,
    ) !void {
        // Build plaintext record: timestamp(8) + name_len(2) + name + text
        const name_len: u16 = @intCast(sender.len);
        const record_len = 8 + 2 + sender.len + text.len;
        const record = try self.allocator.alloc(u8, record_len);
        defer self.allocator.free(record);

        var offset: usize = 0;
        std.mem.writeInt(i64, record[offset..][0..8], timestamp, .big);
        offset += 8;
        std.mem.writeInt(u16, record[offset..][0..2], name_len, .big);
        offset += 2;
        @memcpy(record[offset .. offset + sender.len], sender);
        offset += sender.len;
        @memcpy(record[offset .. offset + text.len], text);

        // Encrypt the record
        const encrypted = try chat_crypto.encrypt(self.allocator, record, encryption_key);
        defer self.allocator.free(encrypted);

        // Write to file: entry_len(4) + encrypted
        const file = try std.fs.cwd().createFile(self.file_path, .{
            .truncate = false,
        });
        defer file.close();

        // Seek to end
        try file.seekFromEnd(0);

        const entry_len: u32 = @intCast(encrypted.len);
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, entry_len, .big);

        try file.writeAll(&len_buf);
        try file.writeAll(encrypted);
    }

    /// A single decrypted history entry.
    pub const HistoryEntry = struct {
        sender: []const u8,
        text: []const u8,
        timestamp: i64,
        /// The raw allocation backing sender and text.
        _backing: []u8,

        pub fn deinit(self: *HistoryEntry, allocator: std.mem.Allocator) void {
            allocator.free(self._backing);
        }
    };

    /// Read all encrypted entries from disk and decrypt them.
    pub fn readAll(
        self: *ChatStorage,
        encryption_key: [chat_crypto.key_length]u8,
    ) !std.ArrayList(HistoryEntry) {
        var entries: std.ArrayList(HistoryEntry) = .{};
        errdefer {
            for (entries.items) |*e| {
                e.deinit(self.allocator);
            }
            entries.deinit(self.allocator);
        }

        const file = std.fs.cwd().openFile(self.file_path, .{}) catch |err| {
            if (err == error.FileNotFound) return entries; // No history yet
            return err;
        };
        defer file.close();

        const file_size = try file.getEndPos();
        if (file_size == 0) return entries;

        const data = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(data);

        const bytes_read = try file.readAll(data);
        if (bytes_read != file_size) return error.IncompleteRead;

        var pos: usize = 0;
        while (pos + 4 <= data.len) {
            const entry_len = std.mem.readInt(u32, data[pos..][0..4], .big);
            pos += 4;

            if (pos + entry_len > data.len) return error.CorruptedHistory;

            const encrypted = data[pos .. pos + entry_len];
            pos += entry_len;

            const record = try chat_crypto.decrypt(self.allocator, encrypted, encryption_key);

            if (record.len < 10) { // 8 + 2 minimum
                self.allocator.free(record);
                return error.CorruptedHistory;
            }

            const timestamp = std.mem.readInt(i64, record[0..8], .big);
            const name_len = std.mem.readInt(u16, record[8..10], .big);

            if (record.len < 10 + name_len) {
                self.allocator.free(record);
                return error.CorruptedHistory;
            }

            const sender = record[10 .. 10 + name_len];
            const text = record[10 + name_len ..];

            try entries.append(self.allocator, HistoryEntry{
                .sender = sender,
                .text = text,
                .timestamp = timestamp,
                ._backing = record,
            });
        }

        return entries;
    }

    /// Delete the history file.
    pub fn clear(self: *ChatStorage) !void {
        std.fs.cwd().deleteFile(self.file_path) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "storage: write and read back" {
    const allocator = std.testing.allocator;
    const test_path = "test_chat_history.bin";

    var store = try ChatStorage.init(allocator, test_path);
    defer store.deinit();

    // Clean up any leftover file from previous test runs
    store.clear() catch {};
    defer store.clear() catch {};

    // Generate a key for encryption
    const alice = chat_crypto.Identity.generate();
    const bob = chat_crypto.Identity.generate();
    const shared_key = try chat_crypto.deriveSharedKey(alice.dh_secret, bob.dh_public);

    // Write some entries
    try store.appendEntry("Alice", "Hello!", 1000, shared_key);
    try store.appendEntry("Bob", "Hi there!", 1001, shared_key);
    try store.appendEntry("Alice", "How are you?", 1002, shared_key);

    // Read them back
    var entries = try store.readAll(shared_key);
    defer {
        for (entries.items) |*e| {
            e.deinit(allocator);
        }
        entries.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 3), entries.items.len);
    try std.testing.expectEqualStrings("Alice", entries.items[0].sender);
    try std.testing.expectEqualStrings("Hello!", entries.items[0].text);
    try std.testing.expectEqualStrings("Bob", entries.items[1].sender);
    try std.testing.expectEqualStrings("Hi there!", entries.items[1].text);
    try std.testing.expectEqual(@as(i64, 1002), entries.items[2].timestamp);
}
