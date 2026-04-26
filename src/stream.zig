const std = @import("std");
const lib = @import("lib.zig");
const sync = @import("sync.zig");

const openssl = lib.openssl;

const posix = std.posix;
const net = std.Io.net;

const Conn = lib.Conn;
const Allocator = std.mem.Allocator;
const NetStream = net.Stream;

const DEFAULT_HOST = "127.0.0.1";

pub const Stream = if (lib.has_openssl) TLSStream else PlainStream;

const TLSStream = struct {
    valid: bool,
    ssl: ?*openssl.SSL,
    socket: posix.socket_t,
    stream: NetStream,

    pub fn connect(allocator: Allocator, opts: Conn.Opts, ctx_: ?*openssl.SSL_CTX) !Stream {
        const plain = try PlainStream.connect(allocator, opts, null);
        errdefer plain.close();

        const socket = plain.stream.socket.handle;

        var ssl: ?*openssl.SSL = null;
        if (ctx_) |ctx| {
            // PostgreSQL TLS starts off as a plain connection which we upgrade
            try writeSocket(plain.stream, &.{ 0, 0, 0, 8, 4, 210, 22, 47 });
            var buf = [1]u8{0};
            _ = try readSocket(plain.stream, &buf);
            if (buf[0] != 'S') {
                return error.SSLNotSupportedByServer;
            }

            ssl = openssl.SSL_new(ctx) orelse return error.SSLNewFailed;
            errdefer openssl.SSL_free(ssl);

            if (opts.host) |host| {
                if (isHostName(host)) {
                    // don't send this for an ip address
                    var owned = false;
                    const h = opts._hostz orelse blk: {
                        owned = true;
                        break :blk try allocator.dupeZ(u8, host);
                    };

                    defer if (owned) {
                        allocator.free(h);
                    };

                    if (openssl.SSL_set_tlsext_host_name(ssl, h.ptr) != 1) {
                        return error.SSLHostNameFailed;
                    }
                }
                switch (opts.tls) {
                    .verify_full => openssl.SSL_set_verify(ssl, openssl.SSL_VERIFY_PEER, null),
                    else => {},
                }
            }

            if (openssl.SSL_set_fd(ssl, if (@import("builtin").os.tag == .windows) @intCast(@intFromPtr(socket)) else socket) != 1) {
                return error.SSLSetFdFailed;
            }

            {
                const ret = openssl.SSL_connect(ssl);
                if (ret != 1) {
                    const verification_code = openssl.SSL_get_verify_result(ssl);
                    if (comptime lib._stderr_tls) {
                        lib.printSSLError();
                    }
                    if (verification_code != openssl.X509_V_OK) {
                        if (comptime lib._stderr_tls) {
                            std.debug.print("ssl verification error: {s}\n", .{openssl.X509_verify_cert_error_string(verification_code)});
                        }
                        return error.SSLCertificationVerificationError;
                    }
                    return error.SSLConnectFailed;
                }
            }
        }

        return .{
            .ssl = ssl,
            .valid = true,
            .socket = socket,
            .stream = plain.stream,
        };
    }

    pub fn close(self: *Stream) void {
        if (self.ssl) |ssl| {
            if (self.valid) {
                _ = openssl.SSL_shutdown(ssl);
                self.valid = false;
            }
            openssl.SSL_free(ssl);
        }
        self.stream.close(sync.io());
    }

    pub fn writeAll(self: *Stream, data: []const u8) !void {
        if (self.ssl) |ssl| {
            const result = openssl.SSL_write(ssl, data.ptr, @intCast(data.len));
            if (result <= 0) {
                self.valid = false;
                return error.SSLWriteFailed;
            }
            return;
        }
        return writeSocket(self.stream, data);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.ssl) |ssl| {
            var read_len: usize = undefined;
            const result = openssl.SSL_read_ex(ssl, buf.ptr, @intCast(buf.len), &read_len);
            if (result <= 0) {
                self.valid = false;
                return error.SSLReadFailed;
            }
            return read_len;
        }

        return readSocket(self.stream, buf);
    }
};

const PlainStream = struct {
    socket: posix.socket_t,
    stream: NetStream,

    pub fn connect(allocator: Allocator, opts: Conn.Opts, _: anytype) !PlainStream {
        _ = allocator;
        const stream = blk: {
            const host = opts.host orelse DEFAULT_HOST;
            if (host.len > 0 and host[0] == '/') {
                if (comptime net.has_unix_sockets == false or std.posix.AF == void) {
                    return error.UnixPathNotSupported;
                }
                const address = try net.UnixAddress.init(host);
                break :blk try address.connect(sync.io());
            }
            const port = opts.port orelse 5432;
            break :blk try tcpConnectToHost(host, port);
        };
        errdefer stream.close(sync.io());

        return .{
            .socket = stream.socket.handle,
            .stream = stream,
        };
    }

    pub fn close(self: *const PlainStream) void {
        self.stream.close(sync.io());
    }

    pub fn writeAll(self: *const PlainStream, data: []const u8) !void {
        return writeSocket(self.stream, data);
    }

    pub fn read(self: *const PlainStream, buf: []u8) !usize {
        return readSocket(self.stream, buf);
    }
};

fn tcpConnectToHost(host: []const u8, port: u16) !NetStream {
    const io_ = sync.io();
    const address = net.IpAddress.resolve(io_, host, port) catch {
        const host_name = try net.HostName.init(host);
        return net.HostName.connect(host_name, io_, port, .{ .mode = .stream });
    };
    return address.connect(io_, .{ .mode = .stream });
}

fn readSocket(stream: NetStream, buf: []u8) !usize {
    var read_buf: [0]u8 = .{};
    var vecs: [1][]u8 = .{buf};
    var reader = stream.reader(sync.io(), &read_buf);
    return reader.interface.readVec(&vecs) catch |err| switch (err) {
        error.ReadFailed => return reader.err orelse err,
        else => return err,
    };
}

fn writeSocket(stream: NetStream, data: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var writer = stream.writer(sync.io(), &buf);
    const w = &writer.interface;
    w.writeAll(data) catch |err| return writer.err orelse err;
    w.flush() catch |err| return writer.err orelse err;
}

fn isHostName(host: []const u8) bool {
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        // IPv6
        return false;
    }
    return std.mem.indexOfNone(u8, host, "0123456789.") != null;
}
