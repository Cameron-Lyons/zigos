const abi = @import("abi.zig");
const vfs = @import("../../fs/vfs.zig");
const socket = @import("../../net/socket.zig");

pub fn vfsErrno(err: vfs.VFSError) i32 {
    return switch (err) {
        vfs.VFSError.NotFound => abi.ENOENT,
        vfs.VFSError.PermissionDenied => abi.EACCES,
        vfs.VFSError.IsDirectory => abi.EISDIR,
        vfs.VFSError.NotDirectory => abi.ENOTDIR,
        vfs.VFSError.AlreadyExists => abi.EEXIST,
        vfs.VFSError.NoSpace => abi.ENOSPC,
        vfs.VFSError.ReadOnly => abi.EROFS,
        vfs.VFSError.OutOfMemory => abi.ENOMEM,
        vfs.VFSError.InvalidPath => abi.EINVAL,
        vfs.VFSError.InvalidOperation => abi.EINVAL,
        vfs.VFSError.DeviceError => abi.EINVAL,
        vfs.VFSError.BrokenPipe => abi.EPIPE,
        vfs.VFSError.TooManyOpenFiles => abi.EMFILE,
        vfs.VFSError.Busy => abi.EBUSY,
    };
}

pub fn socketErrno(err: anyerror) i32 {
    if (err == socket.SocketError.InvalidSocket) return abi.EBADF;
    if (err == socket.SocketError.InvalidAddress) return abi.EINVAL;
    if (err == socket.SocketError.AlreadyConnected) return abi.EISCONN;
    if (err == socket.SocketError.NotConnected) return abi.ENOTCONN;
    if (err == socket.SocketError.ConnectionRefused) return abi.ECONNREFUSED;
    if (err == socket.SocketError.ConnectionReset) return abi.ECONNRESET;
    if (err == socket.SocketError.NoBufferSpace) return abi.ENOBUFS;
    if (err == socket.SocketError.Timeout) return abi.ETIMEDOUT;
    if (err == socket.SocketError.AddressInUse) return abi.EADDRINUSE;
    if (err == socket.SocketError.NotListening) return abi.EINVAL;
    if (err == error.OutOfMemory) return abi.ENOMEM;
    return abi.EINVAL;
}
