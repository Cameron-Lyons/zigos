pub fn networkScopeRank(scope: anytype) u8 {
    return switch (scope) {
        .local_only => 0,
        .trusted_overlay => 1,
        .relay_assisted => 2,
        .unrestricted => 3,
    };
}
