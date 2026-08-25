const std = @import("std");

pub const color_loss_level: u8 = 1;
pub const chroma_subsampling_level: u8 = 0;
pub const max_tile_width: usize = 256;
pub const max_tile_height: usize = 16;
pub const max_tile_pixels: usize = max_tile_width * max_tile_height;
pub const stream_header_bytes: usize = 20;
pub const max_stream_bytes: usize = stream_header_bytes + max_tile_pixels * 3;
pub const max_cache_entries: usize = 256;

pub const Workspace = struct {
    luma: [max_tile_pixels]u8 = undefined,
    orange_chroma: [max_tile_pixels]u8 = undefined,
    green_chroma: [max_tile_pixels]u8 = undefined,
};

pub const EncodeResult = struct {
    bytes: usize,
    raw_plane_bytes: usize,
    compressed_planes: u8,
};

pub const DecodeResult = struct {
    width: usize,
    height: usize,
};

pub const Fingerprint = struct {
    low: u64,
    high: u64,
};

pub const CacheEntry = struct {
    valid: bool = false,
    waiting: bool = false,
    x: u32 = 0,
    y: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    fingerprint: Fingerprint = .{ .low = 0, .high = 0 },
    source_generation: u32 = 0,
    publication_generation: u32 = 0,
    uncached_wire_bytes: usize = 0,
};

pub const CacheDecision = struct {
    slot: usize,
    hit: bool,
    invalidates: bool,
    wait_list: bool,
};

/// Session-local binding between a server tile and the client cache entry
/// with the same numeric slot. A hit is returned only after the caller has
/// fingerprinted pixels from the current RemoteFrame generation.
pub const TileCache = struct {
    usable_entries: usize,
    use_wait_list: bool = false,
    next_publication_generation: u32 = 1,
    entries: [max_cache_entries]CacheEntry = .{CacheEntry{}} ** max_cache_entries,

    pub fn init(client_entries: usize) TileCache {
        return .{ .usable_entries = @min(client_entries, max_cache_entries) };
    }

    pub fn initWithWaitList(client_entries: usize, use_wait_list: bool) TileCache {
        return .{
            .usable_entries = @min(client_entries, max_cache_entries),
            .use_wait_list = use_wait_list,
        };
    }

    pub fn decide(
        self: *const TileCache,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        source_generation: u32,
        fingerprint: Fingerprint,
    ) ?CacheDecision {
        if (self.usable_entries == 0 or width == 0 or height == 0 or source_generation == 0) return null;
        const slot = cacheSlot(x, y, width, height, self.usable_entries);
        const entry = &self.entries[slot];
        const same_binding = (entry.valid or entry.waiting) and
            entry.x == x and entry.y == y and
            entry.width == width and entry.height == height and
            entry.fingerprint.low == fingerprint.low and
            entry.fingerprint.high == fingerprint.high and
            entry.publication_generation != 0;
        return .{
            .slot = slot,
            .hit = entry.valid and same_binding,
            .invalidates = (entry.valid or entry.waiting) and !same_binding,
            .wait_list = self.use_wait_list and !(entry.valid and same_binding) and !(entry.waiting and same_binding),
        };
    }

    pub fn commit(
        self: *TileCache,
        decision: CacheDecision,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        source_generation: u32,
        fingerprint: Fingerprint,
        uncached_wire_bytes: usize,
    ) u32 {
        var entry = &self.entries[decision.slot];
        if (decision.hit) {
            entry.source_generation = source_generation;
            return entry.publication_generation;
        }
        var publication_generation = self.next_publication_generation;
        if (publication_generation == 0) publication_generation = 1;
        self.next_publication_generation = publication_generation +% 1;
        if (self.next_publication_generation == 0) self.next_publication_generation = 1;
        entry.* = .{
            .valid = !decision.wait_list,
            .waiting = decision.wait_list,
            .x = x,
            .y = y,
            .width = width,
            .height = height,
            .fingerprint = fingerprint,
            .source_generation = source_generation,
            .publication_generation = publication_generation,
            .uncached_wire_bytes = uncached_wire_bytes,
        };
        return publication_generation;
    }
};

pub fn fingerprintXrgb32(pixels: []const u32, width: usize, height: usize) ?Fingerprint {
    const pixel_count = checkedPixelCount(width, height) orelse return null;
    if (pixels.len != pixel_count) return null;
    var low: u64 = 0xcbf2_9ce4_8422_2325 ^ @as(u64, width) ^ (@as(u64, height) << 32);
    var high: u64 = 0x9e37_79b9_7f4a_7c15 ^ (@as(u64, width) << 32) ^ @as(u64, height);
    for (pixels, 0..) |pixel, index| {
        const rgb: u64 = pixel & 0x00ff_ffff;
        low = (low ^ rgb ^ @as(u64, index)) *% 0x0000_0100_0000_01b3;
        high ^= rgb +% (@as(u64, index) *% 0x9e37_79b9);
        high = std.math.rotl(u64, high, 17) *% 0xbf58_476d_1ce4_e5b9;
    }
    return .{ .low = low, .high = high };
}

/// Encodes one top-down XRGB32 tile as an MS-RDPNSC bitmap stream.
///
/// R4OS deliberately negotiates the conservative NSCodec profile: no
/// chroma subsampling and a fixed color-loss level of one. Each AYCoCg
/// plane is emitted as NSCodec RLE only when that is strictly smaller than
/// its raw form; otherwise the raw plane is used, as required by the wire
/// format.
pub fn encodeXrgb32(
    pixels: []const u32,
    width: usize,
    height: usize,
    workspace: *Workspace,
    out: []u8,
) ?EncodeResult {
    const pixel_count = checkedPixelCount(width, height) orelse return null;
    if (pixels.len != pixel_count or out.len < stream_header_bytes) return null;

    var i: usize = 0;
    while (i < pixel_count) : (i += 1) {
        const pixel = pixels[i];
        const red: i16 = @intCast((pixel >> 16) & 0xff);
        const green: i16 = @intCast((pixel >> 8) & 0xff);
        const blue: i16 = @intCast(pixel & 0xff);

        // MS-RDPEGDI 3.1.9.1.2, evaluated with signed intermediates.
        const luma = @divTrunc(red + 2 * green + blue, 4);
        const orange = @divTrunc(red - blue, 2);
        const green_chroma = @divTrunc(green - @divTrunc(red + blue, 2), 2);
        if (luma < 0 or luma > 255 or orange < -128 or orange > 127 or green_chroma < -128 or green_chroma > 127) return null;

        workspace.luma[i] = @intCast(luma);
        workspace.orange_chroma[i] = @bitCast(@as(i8, @intCast(orange)));
        workspace.green_chroma[i] = @bitCast(@as(i8, @intCast(green_chroma)));
    }

    var pos: usize = stream_header_bytes;
    var plane_lengths: [3]usize = .{ 0, 0, 0 };
    var compressed_planes: u8 = 0;
    const planes = [_][]const u8{
        workspace.luma[0..pixel_count],
        workspace.orange_chroma[0..pixel_count],
        workspace.green_chroma[0..pixel_count],
    };
    for (planes, 0..) |plane, plane_index| {
        if (pos > out.len or plane.len > out.len - pos) return null;
        const encoded_len = rleEncodePlane(plane, out[pos .. pos + plane.len]);
        if (encoded_len) |length| {
            if (length < plane.len) {
                plane_lengths[plane_index] = length;
                compressed_planes |= @as(u8, 1) << @intCast(plane_index);
                pos += length;
                continue;
            }
        }
        @memcpy(out[pos .. pos + plane.len], plane);
        plane_lengths[plane_index] = plane.len;
        pos += plane.len;
    }

    writeLe32(out[0..4], @intCast(plane_lengths[0]));
    writeLe32(out[4..8], @intCast(plane_lengths[1]));
    writeLe32(out[8..12], @intCast(plane_lengths[2]));
    writeLe32(out[12..16], 0);
    out[16] = color_loss_level;
    out[17] = chroma_subsampling_level;
    out[18] = 0;
    out[19] = 0;

    return .{
        .bytes = pos,
        .raw_plane_bytes = pixel_count * 3,
        .compressed_planes = compressed_planes,
    };
}

/// Decodes the conservative R4OS NSCodec profile. This is kept beside the
/// encoder so host and guest self-tests can compare the visible end state
/// without relying on a second codec implementation.
pub fn decodeXrgb32(
    encoded: []const u8,
    width: usize,
    height: usize,
    workspace: *Workspace,
    out: []u32,
) ?DecodeResult {
    const pixel_count = checkedPixelCount(width, height) orelse return null;
    if (out.len < pixel_count or encoded.len < stream_header_bytes) return null;
    if (encoded[16] != color_loss_level or encoded[17] != chroma_subsampling_level or encoded[18] != 0 or encoded[19] != 0) return null;
    if (readLe32(encoded[12..16]) != 0) return null;

    const plane_lengths = [_]usize{
        @intCast(readLe32(encoded[0..4])),
        @intCast(readLe32(encoded[4..8])),
        @intCast(readLe32(encoded[8..12])),
    };
    const planes = [_][]u8{
        workspace.luma[0..pixel_count],
        workspace.orange_chroma[0..pixel_count],
        workspace.green_chroma[0..pixel_count],
    };
    var pos: usize = stream_header_bytes;
    for (plane_lengths, planes) |length, plane| {
        if (length == 0 or length > pixel_count or pos > encoded.len or length > encoded.len - pos) return null;
        const source = encoded[pos .. pos + length];
        if (length == pixel_count) {
            @memcpy(plane, source);
        } else if (!rleDecodePlane(source, plane)) {
            return null;
        }
        pos += length;
    }
    if (pos != encoded.len) return null;

    var i: usize = 0;
    while (i < pixel_count) : (i += 1) {
        const luma: i16 = workspace.luma[i];
        const orange_reduced: i8 = @bitCast(workspace.orange_chroma[i]);
        const green_reduced: i8 = @bitCast(workspace.green_chroma[i]);
        const orange: i16 = @as(i16, orange_reduced) * 2;
        const green_chroma: i16 = @as(i16, green_reduced) * 2;

        const red = clampByte(luma + @divTrunc(orange - green_chroma, 2));
        const green = clampByte(luma + @divTrunc(green_chroma, 2));
        const blue = clampByte(luma - @divTrunc(orange + green_chroma, 2));
        out[i] = (@as(u32, red) << 16) | (@as(u32, green) << 8) | blue;
    }
    return .{ .width = width, .height = height };
}

/// Returns true only if NSCodec saves at least one eighth of the complete
/// candidate payload against the existing 16-bpp fallback. Small rectangles
/// stay on RLE16/Raw so the fixed fast-path headers never dominate.
pub fn savesWireBytes(encoded_bytes: usize, width: usize, height: usize, codec_overhead: usize) bool {
    const pixel_count = checkedPixelCount(width, height) orelse return false;
    if (pixel_count < 64) return false;
    const row_bytes = width * 2;
    const padded_row_bytes = (row_bytes + 3) & ~@as(usize, 3);
    const fallback_bytes = padded_row_bytes * height;
    if (encoded_bytes > std.math.maxInt(usize) - codec_overhead) return false;
    const candidate_bytes = encoded_bytes + codec_overhead;
    return candidate_bytes < fallback_bytes and candidate_bytes <= fallback_bytes -| (fallback_bytes / 8);
}

fn checkedPixelCount(width: usize, height: usize) ?usize {
    if (width == 0 or height == 0 or width > max_tile_width or height > max_tile_height) return null;
    if (width > std.math.maxInt(usize) / height) return null;
    const count = width * height;
    if (count > max_tile_pixels) return null;
    return count;
}

fn cacheSlot(x: u32, y: u32, width: u32, height: u32, entries: usize) usize {
    var hash = @as(u64, x) *% 0x9e37_79b1;
    hash ^= @as(u64, y) *% 0x85eb_ca77;
    hash ^= @as(u64, width) << 17;
    hash ^= @as(u64, height) << 41;
    hash ^= hash >> 29;
    return @intCast(hash % entries);
}

fn rleEncodePlane(source: []const u8, out: []u8) ?usize {
    if (source.len <= 4) return null;
    const segment_end = source.len - 4;
    // A literal immediately before EndData must not equal its first byte:
    // the decoder would otherwise interpret both bytes as a run marker.
    // Falling back to the raw plane is preferable to emitting an ambiguous
    // NSCODEC_RLE_LITERAL_SEGMENT.
    if (source[segment_end - 1] == source[segment_end] and
        (segment_end == 1 or source[segment_end - 2] != source[segment_end - 1])) return null;
    var src: usize = 0;
    var pos: usize = 0;
    while (src < segment_end) {
        var run: usize = 1;
        while (src + run < segment_end and source[src + run] == source[src]) : (run += 1) {}
        if (run >= 2) {
            if (!putByte(out, &pos, source[src]) or !putByte(out, &pos, source[src])) return null;
            if (run < 256) {
                if (!putByte(out, &pos, @intCast(run - 2))) return null;
            } else {
                if (!putByte(out, &pos, 0xff) or !putLe32(out, &pos, @intCast(run))) return null;
            }
            src += run;
        } else {
            if (!putByte(out, &pos, source[src])) return null;
            src += 1;
        }
    }
    if (pos > out.len or 4 > out.len - pos) return null;
    @memcpy(out[pos .. pos + 4], source[segment_end..]);
    return pos + 4;
}

fn rleDecodePlane(source: []const u8, out: []u8) bool {
    if (out.len <= 4 or source.len < 4) return false;
    const decoded_segment_end = out.len - 4;
    var src: usize = 0;
    var pos: usize = 0;
    while (pos < decoded_segment_end) {
        if (src >= source.len) return false;
        const value = source[src];
        src += 1;
        if (src < source.len and source[src] == value) {
            src += 1;
            if (src >= source.len) return false;
            const factor = source[src];
            src += 1;
            const run: usize = if (factor == 0xff) blk: {
                if (src > source.len or 4 > source.len - src) return false;
                const long_run: usize = @intCast(readLe32(source[src .. src + 4]));
                src += 4;
                if (long_run < 256) return false;
                break :blk long_run;
            } else @as(usize, factor) + 2;
            if (run > decoded_segment_end - pos) return false;
            @memset(out[pos .. pos + run], value);
            pos += run;
        } else {
            out[pos] = value;
            pos += 1;
        }
    }
    if (src > source.len or source.len - src != 4) return false;
    @memcpy(out[decoded_segment_end..], source[src..]);
    return true;
}

fn clampByte(value: i16) u8 {
    if (value <= 0) return 0;
    if (value >= 255) return 255;
    return @intCast(value);
}

fn putByte(out: []u8, pos: *usize, value: u8) bool {
    if (pos.* >= out.len) return false;
    out[pos.*] = value;
    pos.* += 1;
    return true;
}

fn putLe32(out: []u8, pos: *usize, value: u32) bool {
    if (pos.* > out.len or 4 > out.len - pos.*) return false;
    writeLe32(out[pos.* .. pos.* + 4], value);
    pos.* += 4;
    return true;
}

fn writeLe32(out: []u8, value: u32) void {
    out[0] = @intCast(value & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast((value >> 16) & 0xff);
    out[3] = @intCast(value >> 24);
}

fn readLe32(input: []const u8) u32 {
    return @as(u32, input[0]) |
        (@as(u32, input[1]) << 8) |
        (@as(u32, input[2]) << 16) |
        (@as(u32, input[3]) << 24);
}

fn channelDelta(left: u32, right: u32, shift: u5) u8 {
    const a: i32 = @intCast((left >> shift) & 0xff);
    const b: i32 = @intCast((right >> shift) & 0xff);
    return @intCast(@abs(a - b));
}

test "solid tile compresses and decodes to the same visible color" {
    const testing = std.testing;
    var pixels: [max_tile_pixels]u32 = .{0x0033_6699} ** max_tile_pixels;
    var encoded: [max_stream_bytes]u8 = undefined;
    var encode_workspace: Workspace = .{};
    const result = encodeXrgb32(pixels[0..], max_tile_width, max_tile_height, &encode_workspace, encoded[0..]).?;
    try testing.expect(result.bytes < pixels.len * 2);
    try testing.expectEqual(@as(u8, 0b111), result.compressed_planes);
    try testing.expect(savesWireBytes(result.bytes, max_tile_width, max_tile_height, 64));

    var decoded: [max_tile_pixels]u32 = undefined;
    var decode_workspace: Workspace = .{};
    _ = decodeXrgb32(encoded[0..result.bytes], max_tile_width, max_tile_height, &decode_workspace, decoded[0..]).?;
    for (decoded) |pixel| {
        try testing.expect(channelDelta(pixel, pixels[0], 16) <= 2);
        try testing.expect(channelDelta(pixel, pixels[0], 8) <= 2);
        try testing.expect(channelDelta(pixel, pixels[0], 0) <= 2);
    }
}

test "literal-heavy tile remains bounded and does not displace RLE16" {
    const testing = std.testing;
    var pixels: [max_tile_pixels]u32 = undefined;
    for (&pixels, 0..) |*pixel, i| {
        const value: u32 = @intCast(i);
        pixel.* = ((value *% 73) & 0xff) << 16 |
            ((value *% 151) & 0xff) << 8 |
            ((value *% 199) & 0xff);
    }
    var encoded: [max_stream_bytes]u8 = undefined;
    var workspace: Workspace = .{};
    const result = encodeXrgb32(pixels[0..], max_tile_width, max_tile_height, &workspace, encoded[0..]).?;
    try testing.expect(result.bytes <= max_stream_bytes);
    try testing.expect(!savesWireBytes(result.bytes, max_tile_width, max_tile_height, 64));
}

test "mixed colors decode within the fixed CLL1 visible bound" {
    const testing = std.testing;
    var pixels: [max_tile_pixels]u32 = undefined;
    var seed: u32 = 0x5a17_c3e9;
    for (&pixels) |*pixel| {
        seed = seed *% 1664525 +% 1013904223;
        pixel.* = seed & 0x00ff_ffff;
    }
    var encoded: [max_stream_bytes]u8 = undefined;
    var workspace: Workspace = .{};
    const result = encodeXrgb32(pixels[0..], max_tile_width, max_tile_height, &workspace, encoded[0..]).?;
    var decoded: [max_tile_pixels]u32 = undefined;
    _ = decodeXrgb32(encoded[0..result.bytes], max_tile_width, max_tile_height, &workspace, decoded[0..]).?;
    for (pixels, decoded) |source, visible| {
        try testing.expect(channelDelta(source, visible, 16) <= 2);
        try testing.expect(channelDelta(source, visible, 8) <= 2);
        try testing.expect(channelDelta(source, visible, 0) <= 2);
    }
}

test "long runs and terminal literals round trip" {
    const testing = std.testing;
    var source: [600]u8 = .{0x44} ** 600;
    source[596] = 1;
    source[597] = 2;
    source[598] = 3;
    source[599] = 4;
    var encoded: [600]u8 = undefined;
    const length = rleEncodePlane(source[0..], encoded[0..]).?;
    try testing.expect(length < source.len);
    var decoded: [600]u8 = undefined;
    try testing.expect(rleDecodePlane(encoded[0..length], decoded[0..]));
    try testing.expectEqualSlices(u8, source[0..], decoded[0..]);
}

test "invalid geometry capacity and truncated streams fail closed" {
    const testing = std.testing;
    const pixels = [_]u32{0x0012_3456} ** 64;
    var too_small: [19]u8 = undefined;
    var workspace: Workspace = .{};
    try testing.expect(encodeXrgb32(pixels[0..], 8, 8, &workspace, too_small[0..]) == null);
    try testing.expect(encodeXrgb32(pixels[0..], 0, 8, &workspace, too_small[0..]) == null);

    var encoded: [max_stream_bytes]u8 = undefined;
    const result = encodeXrgb32(pixels[0..], 8, 8, &workspace, encoded[0..]).?;
    var decoded: [64]u32 = undefined;
    try testing.expect(decodeXrgb32(encoded[0 .. result.bytes - 1], 8, 8, &workspace, decoded[0..]) == null);
}

test "ambiguous literal before end data keeps the plane raw" {
    const testing = std.testing;
    const source = [_]u8{ 1, 2, 3, 4, 4, 5, 6, 7 };
    var encoded: [source.len]u8 = undefined;
    try testing.expect(rleEncodePlane(source[0..], encoded[0..]) == null);
}

test "tile cache validates generations and invalidates changed content" {
    const testing = std.testing;
    const pixels = [_]u32{0x0012_3456} ** 64;
    const changed = [_]u32{0x0065_4321} ** 64;
    const first_fingerprint = fingerprintXrgb32(pixels[0..], 8, 8).?;
    const changed_fingerprint = fingerprintXrgb32(changed[0..], 8, 8).?;
    var cache = TileCache.init(16);

    const first = cache.decide(20, 40, 8, 8, 7, first_fingerprint).?;
    try testing.expect(!first.hit and !first.invalidates);
    const publication = cache.commit(first, 20, 40, 8, 8, 7, first_fingerprint, 600);
    try testing.expect(publication != 0);

    const same_generation = cache.decide(20, 40, 8, 8, 7, first_fingerprint).?;
    try testing.expect(same_generation.hit);
    try testing.expectEqual(publication, cache.commit(same_generation, 20, 40, 8, 8, 7, first_fingerprint, 0));
    try testing.expectEqual(@as(usize, 600), cache.entries[same_generation.slot].uncached_wire_bytes);

    const validated_new_generation = cache.decide(20, 40, 8, 8, 8, first_fingerprint).?;
    try testing.expect(validated_new_generation.hit);
    _ = cache.commit(validated_new_generation, 20, 40, 8, 8, 8, first_fingerprint, 0);
    try testing.expectEqual(@as(u32, 8), cache.entries[validated_new_generation.slot].source_generation);

    const changed_content = cache.decide(20, 40, 8, 8, 9, changed_fingerprint).?;
    try testing.expect(!changed_content.hit and changed_content.invalidates);
    const replacement = cache.commit(changed_content, 20, 40, 8, 8, 9, changed_fingerprint, 400);
    try testing.expect(replacement != publication);
}

test "waiting-list clients cache on the second encounter and hit on the third" {
    const testing = std.testing;
    const pixels = [_]u32{0x0033_6699} ** 64;
    const fingerprint = fingerprintXrgb32(pixels[0..], 8, 8).?;
    var cache = TileCache.initWithWaitList(16, true);

    const first = cache.decide(4, 12, 8, 8, 1, fingerprint).?;
    try testing.expect(!first.hit and first.wait_list);
    _ = cache.commit(first, 4, 12, 8, 8, 1, fingerprint, 500);
    try testing.expect(cache.entries[first.slot].waiting and !cache.entries[first.slot].valid);

    const second = cache.decide(4, 12, 8, 8, 2, fingerprint).?;
    try testing.expect(!second.hit and !second.wait_list);
    _ = cache.commit(second, 4, 12, 8, 8, 2, fingerprint, 500);
    try testing.expect(!cache.entries[second.slot].waiting and cache.entries[second.slot].valid);

    const third = cache.decide(4, 12, 8, 8, 3, fingerprint).?;
    try testing.expect(third.hit and !third.wait_list);
}
