pub fn sortById(frames: anytype) void {
    var index: usize = 1;
    while (index < frames.len) : (index += 1) {
        const value = frames[index];
        var insert_at = index;
        while (insert_at > 0 and frames[insert_at - 1].id > value.id) : (insert_at -= 1) {
            frames[insert_at] = frames[insert_at - 1];
        }
        frames[insert_at] = value;
    }
}
