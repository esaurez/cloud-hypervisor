// Copyright 2023 Microsoft Corporation. All Rights Reserved.

use libc::{self, EFD_NONBLOCK};
use log::*;
use option_parser::{Toggle, ByteSized};
use option_parser::{OptionParser, OptionParserError};
use std::fmt;
use std::io;
use std::process;
use std::sync::{Arc, Mutex, RwLock};
use std::vec::Vec;
use vhost::vhost_user::message::*;
use vhost::vhost_user::Listener;
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock};
use virtio_bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use vm_memory::{bitmap::AtomicBitmap, GuestMemoryAtomic};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

pub type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to create kill eventfd.
    CreateKillEventFd(io::Error),
    /// Failed to parse configuration string.
    FailedConfigParse(OptionParserError),
    /// Failed to signal used queue.
    FailedSignalingUsedQueue(io::Error),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No socket provided.
    SocketParameterMissing,
    // Missing size
    SizeParameterMissing,
}

pub const SYNTAX: &str = "vhost-user-nimble-net --nimble-net-backend \
\"size=<shmem_size>,socket=<socket_path>,client=on|off,\
num_queues=<number_of_queues>,queue_size=<size_of_each_queue>\"";

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost_user_net_error: {self:?}")
    }
}

impl std::error::Error for Error {}

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserNimbleNetThread {
    kill_evt: EventFd,
}

impl VhostUserNimbleNetThread {
    /// Create a new virtio nimble net device 
    fn new() -> Result<Self> {
        Ok(VhostUserNimbleNetThread {
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
        })
    }
}

pub struct VhostUserNimbleNetBackend {
    _size: u64,
    threads: Vec<Mutex<VhostUserNimbleNetThread>>,
    num_queues: usize,
    queue_size: u16,
    queues_per_thread: Vec<u64>,
    _mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl VhostUserNimbleNetBackend {
    #[allow(clippy::too_many_arguments)]
    fn new(
        size: u64,
        num_queues: usize,
        queue_size: u16,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<Self> {
        let mut queues_per_thread = Vec::new();
        let mut threads = Vec::new();
        let thread = Mutex::new(VhostUserNimbleNetThread::new()?);
        threads.push(thread);
        queues_per_thread.push(1);

        Ok(VhostUserNimbleNetBackend {
            _size: size,
            threads,
            num_queues,
            queue_size,
            queues_per_thread,
            _mem: mem,
        })
    }
}

impl VhostUserBackendMut<VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>, AtomicBitmap>
    for VhostUserNimbleNetBackend
{
    fn num_queues(&self) -> usize {
        self.num_queues
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size as usize
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
    }

    fn set_event_idx(&mut self, _enabled: bool) {}

    fn handle_event(
        &mut self,
        device_event: u16,
        _evset: EventSet,
        _vrings: &[VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        // let mut thread = self.threads[thread_id].lock().unwrap();
        match device_event {
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

        // Ok(false)
    }

    fn exit_event(&self, thread_index: usize) -> Option<EventFd> {
        Some(
            self.threads[thread_index]
                .lock()
                .unwrap()
                .kill_evt
                .try_clone()
                .unwrap(),
        )
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }

    fn update_memory(
        &mut self,
        _mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> VhostUserBackendResult<()> {
        // panic
        panic!("update_memory not implemented for VhostUserNimbleNetBackend")
    }
}

pub struct VhostUserNimbleNetBackendConfig {
    pub size: u64,
    pub socket: String,
    pub num_queues: usize,
    pub queue_size: u16,
    pub client: bool,
}

impl VhostUserNimbleNetBackendConfig {
    pub fn parse(backend: &str) -> Result<Self> {
        let mut parser = OptionParser::new();

        parser
            .add("size")
            .add("socket")
            .add("client")
            .add("num_queues")
            .add("queue_size");

        parser.parse(backend).map_err(Error::FailedConfigParse)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::FailedConfigParse)?
            .map(|v| v.0).ok_or(Error::SizeParameterMissing)?;

        let socket = parser.get("socket").ok_or(Error::SocketParameterMissing)?;

        let client = parser
            .convert::<Toggle>("client")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(Toggle(false))
            .0;


        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(2);
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(2);


        Ok(VhostUserNimbleNetBackendConfig {
            size,
            socket,
            client,
            num_queues,
            queue_size,
        })
    }
}

pub fn start_nimble_net_backend(backend_command: &str) {
    let backend_config = match VhostUserNimbleNetBackendConfig::parse(backend_command) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed parsing parameters {e:?}");
            process::exit(1);
        }
    };

    let mem = GuestMemoryAtomic::new(GuestMemoryMmap::new());

    let nimble_net_backend = Arc::new(RwLock::new(
        VhostUserNimbleNetBackend::new(
            backend_config.size,
            backend_config.num_queues,
            backend_config.queue_size,
            mem.clone(),
        )
        .unwrap(),
    ));

    let mut nimble_net_daemon = VhostUserDaemon::new(
        "vhost-user-nimble-net-backend".to_string(),
        nimble_net_backend.clone(),
        mem,
    )
    .unwrap();

    let epoll_handlers = nimble_net_daemon.get_epoll_handlers();
    if epoll_handlers.len() != nimble_net_backend.read().unwrap().threads.len() {
        error!("Number of vring workers must be identical to the number of backend threads");
        process::exit(1);
    }

    if let Err(e) = if backend_config.client {
        nimble_net_daemon.start_client(&backend_config.socket)
    } else {
        nimble_net_daemon.start(Listener::new(&backend_config.socket, true).unwrap())
    } {
        error!(
            "failed to start daemon for vhost-user-net with error: {:?}",
            e
        );
        process::exit(1);
    }

    if let Err(e) = nimble_net_daemon.wait() {
        error!("Error from the main thread: {:?}", e);
    }

    for thread in nimble_net_backend.read().unwrap().threads.iter() {
        if let Err(e) = thread.lock().unwrap().kill_evt.write(1) {
            error!("Error shutting down worker thread: {:?}", e)
        }
    }
}
