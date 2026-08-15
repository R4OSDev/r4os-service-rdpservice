pub const max_session_width: u32 = 8192;
pub const max_session_height: u32 = 8192;
pub const tile_pixels: u32 = 256;
pub const rle_alignment_pixels: u32 = 4;

pub const SessionGeometry = struct {
    width: u32,
    height: u32,
};

pub const Rect = struct {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
};

pub const TileEncoding = enum {
    rle16,
    raw16,
    raw32,
};

pub const TilePlan = struct {
    width: u32,
    encoding: TileEncoding,
};

pub const ContentMetrics = struct {
    checksum: u32 = 0,
    non_black_pixels: u32 = 0,
};

pub fn sessionGeometry(width: u32, height: u32) ?SessionGeometry {
    if (width == 0 or height == 0) return null;
    if (width > max_session_width or height > max_session_height) return null;
    return .{ .width = width, .height = height };
}

pub fn stripeRect(geometry: SessionGeometry, stripe_y: u32, stripe_height: u32) ?Rect {
    if (stripe_height == 0 or stripe_y >= geometry.height) return null;
    return .{
        .x = 0,
        .y = stripe_y,
        .width = geometry.width,
        .height = @min(stripe_height, geometry.height - stripe_y),
    };
}

pub fn clipRect(geometry: SessionGeometry, x: u32, y: u32, width: u32, height: u32) ?Rect {
    if (width == 0 or height == 0 or x >= geometry.width or y >= geometry.height) return null;
    return .{
        .x = x,
        .y = y,
        .width = @min(width, geometry.width - x),
        .height = @min(height, geometry.height - y),
    };
}

pub fn alignRectForRle(geometry: SessionGeometry, rect: Rect) Rect {
    const x0 = rect.x & ~(rle_alignment_pixels - 1);
    var x1 = rect.x + rect.width;
    x1 = (x1 + rle_alignment_pixels - 1) & ~(rle_alignment_pixels - 1);
    if (x1 > geometry.width) x1 = geometry.width;
    return .{
        .x = x0,
        .y = rect.y,
        .width = x1 - x0,
        .height = rect.height,
    };
}

pub fn nextTile(remaining: u32, compress_rle16: bool) ?TilePlan {
    if (remaining == 0) return null;
    const available = @min(remaining, tile_pixels);
    if (!compress_rle16) return .{ .width = available, .encoding = .raw32 };

    const aligned = available & ~(rle_alignment_pixels - 1);
    if (aligned != 0) return .{ .width = aligned, .encoding = .rle16 };
    return .{ .width = available, .encoding = .raw16 };
}

pub fn updateContentMetrics(initial: ContentMetrics, pixels: []const u32, start_index: u32) ContentMetrics {
    var out = initial;
    var i: usize = 0;
    while (i < pixels.len) : (i += 1) {
        const rgb = pixels[i] & 0x00ff_ffff;
        if (rgb == 0) continue;
        const index = start_index +% @as(u32, @intCast(i));
        out.checksum +%= rgb ^ (index *% 0x9e37_79b1);
        out.checksum = (out.checksum << 5) | (out.checksum >> 27);
        out.non_black_pixels +%= 1;
    }
    return out;
}

test "session geometry accepts common hardware modes and rejects its boundary" {
    const testing = @import("std").testing;

    try testing.expectEqual(SessionGeometry{ .width = 1280, .height = 720 }, sessionGeometry(1280, 720).?);
    try testing.expectEqual(SessionGeometry{ .width = 1366, .height = 768 }, sessionGeometry(1366, 768).?);
    try testing.expectEqual(SessionGeometry{ .width = 1920, .height = 1080 }, sessionGeometry(1920, 1080).?);
    try testing.expectEqual(SessionGeometry{ .width = 3840, .height = 2160 }, sessionGeometry(3840, 2160).?);
    try testing.expectEqual(SessionGeometry{ .width = 8192, .height = 8192 }, sessionGeometry(8192, 8192).?);
    try testing.expect(sessionGeometry(0, 720) == null);
    try testing.expect(sessionGeometry(8193, 1080) == null);
    try testing.expect(sessionGeometry(1920, 8193) == null);
}

test "stripe and dirty rectangles stay inside the announced session" {
    const testing = @import("std").testing;
    const geometry = sessionGeometry(1366, 768).?;

    try testing.expectEqual(Rect{ .x = 0, .y = 720, .width = 1366, .height = 48 }, stripeRect(geometry, 720, 48).?);
    try testing.expect(stripeRect(geometry, 768, 48) == null);
    try testing.expectEqual(Rect{ .x = 1364, .y = 766, .width = 2, .height = 2 }, clipRect(geometry, 1364, 766, 20, 20).?);
    try testing.expect(clipRect(geometry, 1366, 0, 1, 1) == null);

    const aligned = alignRectForRle(geometry, .{ .x = 1365, .y = 4, .width = 1, .height = 1 });
    try testing.expectEqual(Rect{ .x = 1364, .y = 4, .width = 2, .height = 1 }, aligned);
}

test "odd hardware widths keep a 16 bit raw tail" {
    const testing = @import("std").testing;

    const widths = [_]u32{ 1280, 1365, 1366, 1920, 3840, 8192 };
    for (widths) |width| {
        var remaining = width;
        var total: u32 = 0;
        var raw_tail: u32 = 0;
        while (nextTile(remaining, true)) |tile| {
            try testing.expect(tile.width > 0 and tile.width <= tile_pixels);
            switch (tile.encoding) {
                .rle16 => try testing.expectEqual(@as(u32, 0), tile.width & (rle_alignment_pixels - 1)),
                .raw16 => raw_tail += tile.width,
                .raw32 => return error.UnexpectedRaw32Tile,
            }
            total += tile.width;
            remaining -= tile.width;
        }
        try testing.expectEqual(width, total);
        try testing.expectEqual(width & (rle_alignment_pixels - 1), raw_tail);
    }

    try testing.expectEqual(TilePlan{ .width = 256, .encoding = .raw32 }, nextTile(300, false).?);
}

test "black metric is zero and colored content is position sensitive" {
    const testing = @import("std").testing;
    const black = [_]u32{ 0, 0xff00_0000, 0, 0 };
    const black_metrics = updateContentMetrics(.{}, black[0..], 100);
    try testing.expectEqual(@as(u32, 0), black_metrics.checksum);
    try testing.expectEqual(@as(u32, 0), black_metrics.non_black_pixels);

    const colored = [_]u32{ 0, 0x0012_3456, 0x00ab_cdef, 0 };
    const first = updateContentMetrics(.{}, colored[0..], 100);
    const moved = updateContentMetrics(.{}, colored[0..], 101);
    try testing.expectEqual(@as(u32, 2), first.non_black_pixels);
    try testing.expect(first.checksum != 0);
    try testing.expect(first.checksum != moved.checksum);
}
