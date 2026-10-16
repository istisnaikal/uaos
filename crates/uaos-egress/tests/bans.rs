// SPDX-License-Identifier: Apache-2.0

//! Canaries for every ban in `clippy.toml` (review WP3.A5, round 5, L2). Each function below
//! calls one banned item under `#[expect(...)]` and is never run. If a ban stops firing (its path
//! no longer resolves, an item moved upstream, a typo, a wrong kind, a first segment that names no
//! crate), its expectation goes unfulfilled, and `unfulfilled_lint_expectations` fails clippy
//! under `-D warnings` on every system that compiles the canary. Bans that exist only on some
//! systems are compiled only there, so each CI system proves its own. `every_ban_has_a_canary`
//! keeps this file complete. `getrandom::fill` is not a dependency here; its canary lives in
//! `uaos-platform`'s tests.

#![allow(clippy::unwrap_used, reason = "test harness")]

mod canaries {
    #![allow(dead_code, reason = "canaries are compiled by clippy and never run")]

    use std::time::Duration;

    // ── Clocks, processes, files, environment ─────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn system_time_now() {
        // canary: `std::time::SystemTime::now`
        let _canary = std::time::SystemTime::now();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn instant_now() {
        // canary: `std::time::Instant::now`
        let _canary = std::time::Instant::now();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn thread_spawn() {
        // canary: `std::thread::spawn`
        let _canary = std::thread::spawn(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn command_new() {
        // canary: `std::process::Command::new`
        let _canary = std::process::Command::new("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_write() {
        // canary: `std::fs::write`
        let _canary = std::fs::write("canary", b"");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_read() {
        // canary: `std::fs::read`
        let _canary = std::fs::read("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_read_to_string() {
        // canary: `std::fs::read_to_string`
        let _canary = std::fs::read_to_string("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_remove_file() {
        // canary: `std::fs::remove_file`
        let _canary = std::fs::remove_file("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_rename() {
        // canary: `std::fs::rename`
        let _canary = std::fs::rename("canary", "canary2");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_create_dir_all() {
        // canary: `std::fs::create_dir_all`
        let _canary = std::fs::create_dir_all("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn file_create() {
        // canary: `std::fs::File::create`
        let _canary = std::fs::File::create("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn file_open() {
        // canary: `std::fs::File::open`
        let _canary = std::fs::File::open("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn open_options_open() {
        // canary: `std::fs::OpenOptions::open`
        let _canary = std::fs::OpenOptions::new().open("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn env_var() {
        // canary: `std::env::var`
        let _canary = std::env::var("CANARY");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn env_var_os() {
        // canary: `std::env::var_os`
        let _canary = std::env::var_os("CANARY");
    }

    // ── Outbound connections, resolution, UDP ────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_tcp_connect() {
        // canary: `std::net::TcpStream::connect`
        let _canary = std::net::TcpStream::connect("canary.invalid:1");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_tcp_connect_timeout(addr: &std::net::SocketAddr) {
        // canary: `std::net::TcpStream::connect_timeout`
        let _canary = std::net::TcpStream::connect_timeout(addr, Duration::ZERO);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_udp_bind() {
        // canary: `std::net::UdpSocket::bind`
        let _canary = std::net::UdpSocket::bind("0.0.0.0:0");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn to_socket_addrs() {
        // canary: `std::net::ToSocketAddrs::to_socket_addrs`
        use std::net::ToSocketAddrs as _;
        let _canary = "canary.invalid:1".to_socket_addrs();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_connect() {
        // canary: `tokio::net::TcpStream::connect`
        let _canary = tokio::net::TcpStream::connect("canary.invalid:1");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_lookup_host() {
        // canary: `tokio::net::lookup_host`
        let _canary = tokio::net::lookup_host("canary.invalid:1");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_socket_connect(socket: tokio::net::TcpSocket, addr: std::net::SocketAddr) {
        // canary: `tokio::net::TcpSocket::connect`
        let _canary = socket.connect(addr);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_udp_bind() {
        // canary: `tokio::net::UdpSocket::bind`
        let _canary = tokio::net::UdpSocket::bind("0.0.0.0:0");
    }

    // ── Another HTTP client ──────────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn http_connector_new() {
        // canary: `hyper_util::client::legacy::connect::HttpConnector::new`
        let _canary = hyper_util::client::legacy::connect::HttpConnector::new();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn http_connector_new_with_resolver() {
        // canary: `hyper_util::client::legacy::connect::HttpConnector::new_with_resolver`
        let _canary = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn build_http(builder: &hyper_util::client::legacy::Builder) {
        // canary: `hyper_util::client::legacy::Builder::build_http`
        let _canary = builder.build_http::<http_body_util::Empty<bytes::Bytes>>();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn gai_resolver_new() {
        // canary: `hyper_util::client::legacy::connect::dns::GaiResolver::new`
        let _canary = hyper_util::client::legacy::connect::dns::GaiResolver::new();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn tokio_executor() {
        // canary: `hyper_util::rt::TokioExecutor`
        let _canary = hyper_util::rt::TokioExecutor::new();
    }

    /// An executor that runs nothing, so a canary can name `Door::new` without spawning.
    #[derive(Clone)]
    struct NoExecutor;

    impl<F> hyper::rt::Executor<F> for NoExecutor {
        fn execute(&self, _future: F) {}
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    #[allow(clippy::no_effect_underscore_binding, reason = "the canary only names the function")]
    fn door_new() {
        // canary: `uaos_egress::Door::new`
        let _canary = uaos_egress::Door::new::<NoExecutor>;
    }

    // ── Listening ────────────────────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_tcp_listen() {
        // canary: `std::net::TcpListener::bind`
        let _canary = std::net::TcpListener::bind("127.0.0.1:0");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_listen() {
        // canary: `tokio::net::TcpListener::bind`
        let _canary = tokio::net::TcpListener::bind("127.0.0.1:0");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_socket_listen(socket: tokio::net::TcpSocket) {
        // canary: `tokio::net::TcpSocket::listen`
        let _canary = socket.listen(1);
    }

    // ── Spawning ─────────────────────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn task_spawn() {
        // canary: `tokio::task::spawn`
        let _canary = tokio::task::spawn(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn task_spawn_blocking() {
        // canary: `tokio::task::spawn_blocking`
        let _canary = tokio::task::spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn task_spawn_local() {
        // canary: `tokio::task::spawn_local`
        let _canary = tokio::task::spawn_local(async {});
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn join_set() {
        // canary: `tokio::task::JoinSet`
        let _canary = tokio::task::JoinSet::<()>::new();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn local_set() {
        // canary: `tokio::task::LocalSet`
        let _canary = tokio::task::LocalSet::new();
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn(set: &mut tokio::task::JoinSet<()>) {
        // canary: `tokio::task::JoinSet::spawn`
        let _canary = set.spawn(async {});
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_blocking(set: &mut tokio::task::JoinSet<()>) {
        // canary: `tokio::task::JoinSet::spawn_blocking`
        let _canary = set.spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_on(set: &mut tokio::task::JoinSet<()>, handle: &tokio::runtime::Handle) {
        // canary: `tokio::task::JoinSet::spawn_on`
        let _canary = set.spawn_on(async {}, handle);
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_local(set: &mut tokio::task::JoinSet<()>) {
        // canary: `tokio::task::JoinSet::spawn_local`
        let _canary = set.spawn_local(async {});
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_local_on(set: &mut tokio::task::JoinSet<()>, local: &tokio::task::LocalSet) {
        // canary: `tokio::task::JoinSet::spawn_local_on`
        let _canary = set.spawn_local_on(async {}, local);
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_blocking_on(set: &mut tokio::task::JoinSet<()>, handle: &tokio::runtime::Handle) {
        // canary: `tokio::task::JoinSet::spawn_blocking_on`
        let _canary = set.spawn_blocking_on(|| (), handle);
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn local_set_spawn_local(local: &tokio::task::LocalSet) {
        // canary: `tokio::task::LocalSet::spawn_local`
        let _canary = local.spawn_local(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn handle_spawn(handle: &tokio::runtime::Handle) {
        // canary: `tokio::runtime::Handle::spawn`
        let _canary = handle.spawn(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn handle_spawn_blocking(handle: &tokio::runtime::Handle) {
        // canary: `tokio::runtime::Handle::spawn_blocking`
        let _canary = handle.spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn runtime_spawn(runtime: &tokio::runtime::Runtime) {
        // canary: `tokio::runtime::Runtime::spawn`
        let _canary = runtime.spawn(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn runtime_spawn_blocking(runtime: &tokio::runtime::Runtime) {
        // canary: `tokio::runtime::Runtime::spawn_blocking`
        let _canary = runtime.spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn thread_builder_spawn() {
        // canary: `std::thread::Builder::spawn`
        let _canary = std::thread::Builder::new().spawn(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn thread_scope() {
        // canary: `std::thread::scope`
        std::thread::scope(|_| ());
    }

    // ── Deterministic collections ────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn hash_map() {
        // canary: `std::collections::HashMap`
        let _canary = std::collections::HashMap::<u8, u8>::new();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn hash_set() {
        // canary: `std::collections::HashSet`
        let _canary = std::collections::HashSet::<u8>::new();
    }

    // ── Local IPC and local listeners, Unix (review WP3.A5, rounds 3 to 5) ────────────────

    #[cfg(unix)]
    mod unix {
        use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_stream_connect() {
            // canary: `std::os::unix::net::UnixStream::connect`
            let _canary = UnixStream::connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_stream_connect_addr(addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixStream::connect_addr`
            let _canary = UnixStream::connect_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_bind() {
            // canary: `std::os::unix::net::UnixDatagram::bind`
            let _canary = UnixDatagram::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_bind_addr(addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixDatagram::bind_addr`
            let _canary = UnixDatagram::bind_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_unbound() {
            // canary: `std::os::unix::net::UnixDatagram::unbound`
            let _canary = UnixDatagram::unbound();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_connect(socket: &UnixDatagram) {
            // canary: `std::os::unix::net::UnixDatagram::connect`
            let _canary = socket.connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_connect_addr(socket: &UnixDatagram, addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixDatagram::connect_addr`
            let _canary = socket.connect_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_send_to(socket: &UnixDatagram) {
            // canary: `std::os::unix::net::UnixDatagram::send_to`
            let _canary = socket.send_to(b"", "/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_send_to_addr(socket: &UnixDatagram, addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixDatagram::send_to_addr`
            let _canary = socket.send_to_addr(b"", addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_listener_bind() {
            // canary: `std::os::unix::net::UnixListener::bind`
            let _canary = UnixListener::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_listener_bind_addr(addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixListener::bind_addr`
            let _canary = UnixListener::bind_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_stream_connect() {
            // canary: `tokio::net::UnixStream::connect`
            let _canary = tokio::net::UnixStream::connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_stream_connect_addr(addr: &tokio::net::unix::SocketAddr) {
            // canary: `tokio::net::UnixStream::connect_addr`
            let _canary = tokio::net::UnixStream::connect_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_socket_connect(socket: tokio::net::UnixSocket) {
            // canary: `tokio::net::UnixSocket::connect`
            let _canary = socket.connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_socket_datagram(socket: tokio::net::UnixSocket) {
            // canary: `tokio::net::UnixSocket::datagram`
            let _canary = socket.datagram();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_socket_listen(socket: tokio::net::UnixSocket) {
            // canary: `tokio::net::UnixSocket::listen`
            let _canary = socket.listen(1);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_bind() {
            // canary: `tokio::net::UnixDatagram::bind`
            let _canary = tokio::net::UnixDatagram::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_unbound() {
            // canary: `tokio::net::UnixDatagram::unbound`
            let _canary = tokio::net::UnixDatagram::unbound();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_connect(socket: &tokio::net::UnixDatagram) {
            // canary: `tokio::net::UnixDatagram::connect`
            let _canary = socket.connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_send_to(socket: &tokio::net::UnixDatagram) {
            // canary: `tokio::net::UnixDatagram::send_to`
            let _canary = socket.send_to(b"", "/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_listener_bind() {
            // canary: `tokio::net::UnixListener::bind`
            let _canary = tokio::net::UnixListener::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_listener_bind_addr(addr: &tokio::net::unix::SocketAddr) {
            // canary: `tokio::net::UnixListener::bind_addr`
            let _canary = tokio::net::UnixListener::bind_addr(addr);
        }
    }

    // ── Named pipes, Windows ─────────────────────────────────────────────────────────────

    #[cfg(windows)]
    mod windows {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn pipe_client_open() {
            // canary: `tokio::net::windows::named_pipe::ClientOptions::open`
            let _canary = ClientOptions::new().open("canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn pipe_server_create() {
            // canary: `tokio::net::windows::named_pipe::ServerOptions::create`
            let _canary = ServerOptions::new().create("canary");
        }
    }
}

/// Every path `clippy.toml` bans has a canary in this file, or in `uaos-platform`'s for crates
/// this one cannot name, so adding a ban without proving it fires fails the tests.
#[test]
fn every_ban_has_a_canary() {
    let config = include_str!("../../../clippy.toml");
    let here = include_str!("bans.rs");
    let platform = include_str!("../../uaos-platform/tests/bans.rs");
    let missing: Vec<&str> = config
        .lines()
        .filter_map(|line| line.split("path = \"").nth(1)?.split('"').next())
        .filter(|path| {
            let marker = format!("// canary: `{path}`");
            !here.contains(&marker) && !platform.contains(&marker)
        })
        .collect();
    assert!(missing.is_empty(), "bans without a canary: {missing:?}");
}
