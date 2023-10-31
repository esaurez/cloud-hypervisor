// Copyright 2023 Microsoft Corporation. All Rights Reserved.

pub mod base;

use libc::{self, EFD_NONBLOCK};
use log::*;
use option_parser::{Toggle, ByteSized};
use option_parser::OptionParser;
use vm_memory::{GuestAddress, Address, GuestAddressSpace, GuestMemory, GuestMemoryRegion, Bytes};
use std::collections::HashMap;
use std::mem::size_of;
use std::ops::Deref;
use std::os::raw::c_char;
use std::io;
use std::process;
use std::sync::{Arc, Mutex, RwLock, RwLockWriteGuard};
use std::vec::Vec;
use vhost::vhost_user::message::*;
use vhost::vhost_user::Listener;
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringState, VringT};
use virtio_bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_queue::{DescriptorChain, QueueT};
use vm_memory::{bitmap::AtomicBitmap, GuestMemoryAtomic, ByteValued, GuestMemoryLoadGuard};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use base::{Error, Result, Segment, GuestMemoryMmap, SegmentsManager, SharedMemory};

type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioNimbleReqHeader {
    type_: u8,
    _reserved: [u8; 7],
}

/// Set address request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioNimbleReqSetAddr {
    addr: u64,
}

const NAME_LENGTH: usize = 128;

/// Get segment request
#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct VirtioNimbleReqGetSegment {
    name: [c_char; NAME_LENGTH],
}

impl Default for VirtioNimbleReqGetSegment {
    fn default() -> Self {
        Self {
            name: [0; NAME_LENGTH],
        }
    }
}

// Create segment request
#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct VirtioNimbleReqCreateSegment {
    name: [c_char; NAME_LENGTH],
    size: u64,
}

impl Default for VirtioNimbleReqCreateSegment {
    fn default() -> Self {
        Self {
            name: [0; NAME_LENGTH],
            size: 0,
        }
    }
}

// Get segment response
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioNimbleRespGet {
    size: u64,
    offset: u64,
}

// Create segment response
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioNimbleRespCreate {
    offset: u64,
}

// Set address response
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioNimbleRespSetAddr {
    status: u8,
    _reserved: [u8; 7],
}

const VIRTIO_NIMBLE_REQ_TYPE_SET_ADDR: u8 =  0;
const VIRTIO_NIMBLE_REQ_TYPE_GET_SEGMENT: u8 = 1;
const VIRTIO_NIMBLE_REQ_TYPE_CREATE_SEGMENT: u8 = 2;

const VIRTIO_NIMBLE_RESP_OK: u8 = 0;

unsafe impl ByteValued for VirtioNimbleReqHeader {}
unsafe impl ByteValued for VirtioNimbleReqSetAddr {}
unsafe impl ByteValued for VirtioNimbleReqGetSegment {}
unsafe impl ByteValued for VirtioNimbleReqCreateSegment {}
unsafe impl ByteValued for VirtioNimbleRespGet {}
unsafe impl ByteValued for VirtioNimbleRespCreate {}
unsafe impl ByteValued for VirtioNimbleRespSetAddr {}

pub struct ShmemManager {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    region_addr: Option<GuestAddress>,
    segment_map: HashMap<String, Segment>,
    pub size: u64,
    current_offset: u64,
}

impl ShmemManager {
    pub fn new(
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        region_size: u64
    ) -> Self {
        ShmemManager {
            mem,
            region_addr: None,
            segment_map: HashMap::new(),
            size: region_size,
            current_offset: 0,
        }
    }

    pub fn initialized(&self) -> bool {
        self.region_addr.is_some()
    }

    pub fn init(
        &mut self,
        gpa: GuestAddress,
    ) -> Result<()> {
        let mem_guard = self.mem.memory();
        let region = mem_guard.find_region(gpa).ok_or(Error::RegionNotFound)?;
        // The regions used by the shared memory where explicitly created to match
        // Check that both size and starting address match
        if region.start_addr() != gpa {
            return Err(Error::RegionAddressInvalid(region.start_addr().0, gpa.0));
        }
        if region.len() != self.size {
            return Err(Error::RegionSizeInvalid(region.len(), self.size));
        }
        self.region_addr.replace(gpa);
        Ok(())
    }
}

impl SegmentsManager for ShmemManager {
    fn create_region(&mut self, segment_name: &str, segment_size: u64) -> Result<Segment> {
        if self.segment_map.contains_key(segment_name) {
            return Ok(self.segment_map.get(segment_name).ok_or(Error::SegmentRetrieval)?.clone());
        }

        if self.current_offset + segment_size > self.size {
            return Err(Error::SegmentTooLarge);
        }

        let offset = self.current_offset;
        self.current_offset += segment_size;

        let segment = Segment {
            offset,
            size: segment_size,
        };
        self.segment_map.insert(segment_name.to_string(), segment.clone());
        Ok(segment)
    }

    fn get_region(&mut self, segment_name: &str) -> Result<Segment> {
        match self.segment_map.get(segment_name) {
            Some(segment) => Ok(segment.clone()),
            None => Err(Error::RegionNotFound),
        }
    }

    fn mmap_region(&mut self, segment: &Segment) -> Result<SharedMemory> {
        let offset = segment.offset as usize;
        let size = segment.size as usize;
        let region_addr = match self.region_addr {
            Some(addr) => { addr },
            None => { return Err(Error::SegmentManagerInitialization); }
        };
        if offset + size > (self.size as usize){
            return Err(Error::SegmentTooLarge)
        }
        let mem = self.mem.clone();
        SharedMemory::new(mem, region_addr, offset, size)
    }
}

pub const SYNTAX: &str = "vhost-user-nimble-net --nimble-net-backend \
\"size=<shmem_size>,socket=<socket_path>,client=on|off,\
num_queues=<number_of_queues>,queue_size=<size_of_each_queue>\"";

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserNimbleNetThread {
    event_idx: bool,
    kill_evt: EventFd,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    segment_manager: Arc<Mutex<ShmemManager>>,
}

impl VhostUserNimbleNetThread {
    /// Create a new virtio nimble net device 
    fn new(
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        shmem_manager: Arc<Mutex<ShmemManager>>
    ) -> Result<Self> {
        Ok(VhostUserNimbleNetThread {
            event_idx: false,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            mem,
            segment_manager: shmem_manager,
        })
    }

    fn handle(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
    ) -> Result<usize> {
        let desc = desc_chain
            .next()
            .ok_or(Error::DescriptorChainTooShort)
            .map_err(|e| {
                error!("Missing head descriptor");
                e
            })?;
        // The descriptor contains the request type which MUST be readable.
        if desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        if (desc.len() as usize) < size_of::<VirtioNimbleReqHeader>() {
            return Err(Error::InvalidRequest);
        }

        let req_head: VirtioNimbleReqHeader = desc_chain
            .memory()
            .read_obj(desc.addr())
            .map_err(Error::GuestMemory)?;

        let req_offset = size_of::<VirtioNimbleReqHeader>();
        let desc_size_left = (desc.len() as usize) - req_offset;
        let req_addr = if let Some(addr) = desc.addr().checked_add(req_offset as u64) {
            addr
        } else {
            return Err(Error::InvalidRequest);
        };

        let reply: Result<Vec<u8>> = match req_head.type_ {
            VIRTIO_NIMBLE_REQ_TYPE_SET_ADDR => {
                self.process_set_address(desc_chain, req_addr, desc_size_left)
            },
            VIRTIO_NIMBLE_REQ_TYPE_GET_SEGMENT => {
                self.process_get_segment(desc_chain, req_addr, desc_size_left)
            },
            VIRTIO_NIMBLE_REQ_TYPE_CREATE_SEGMENT => {
                self.process_create_segment(desc_chain, req_addr, desc_size_left)
            },
            _ => {
                Err(Error::InvalidRequest)
            }
        };

        let reply_vec  = reply?;

        let resp_desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;

        desc_chain
            .memory()
            .write_slice(reply_vec.as_slice(), resp_desc.addr())
            .map_err(Error::GuestMemory)?;

        Ok(reply_vec.len())
    }


    fn process_set_address(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>, 
        req_addr: GuestAddress,
        remaining_space: usize,
    ) -> Result<Vec<u8>> {
        let mut response: Vec<u8> = Vec::new();
        if remaining_space != size_of::<VirtioNimbleReqSetAddr>() {
            return Err(Error::InvalidRequest);
        }

        let req: VirtioNimbleReqSetAddr = desc_chain
            .memory()
            .read_obj(req_addr as GuestAddress)
            .map_err(Error::GuestMemory)?;

        let mut sm = self.segment_manager.lock().map_err(|e|{Error::BackendLock { error: e.to_string() }})?;
        if sm.initialized() {
            return Err(Error::InvalidRequest)
        }

        sm.init(GuestAddress::new(req.addr))?;

        let resp = VirtioNimbleRespSetAddr {
            status: VIRTIO_NIMBLE_RESP_OK,
            ..Default::default()
        };
        response.extend_from_slice(resp.as_slice());
        Ok(response)
    }

    fn process_get_segment(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>, 
        req_addr: GuestAddress,
        remaining_space: usize,
    ) -> Result<Vec<u8>> {
        let mut response: Vec<u8> = Vec::new();
        if remaining_space != size_of::<VirtioNimbleReqGetSegment>() {
            return Err(Error::InvalidRequest);
        }

        let req: VirtioNimbleReqGetSegment = desc_chain
            .memory()
            .read_obj(req_addr as GuestAddress)
            .map_err(Error::GuestMemory)?;

        // Cast name to &str
        let name_cstr = unsafe { std::ffi::CStr::from_ptr(req.name.as_ptr()) };
        let str_slice = name_cstr.to_str().map_err(Error::StringConversion)?;

        let mut sm = self.segment_manager.lock().map_err(|e|{Error::BackendLock { error: e.to_string() }})?;
        if !sm.initialized() {
            return Err(Error::SegmentManagerInitialization)
        }
        let region = sm.get_region(str_slice)?;
        let resp = VirtioNimbleRespGet {
            size: region.size,
            offset: region.offset,
        };
        response.extend_from_slice(resp.as_slice());
            
        Ok(response)
    }

    fn process_create_segment(
        &mut self, 
        desc_chain:  &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>, 
        req_addr: GuestAddress,
        remaining_space: usize,
    ) -> Result<Vec<u8>> {
        let mut response: Vec<u8> = Vec::new();
        if remaining_space != size_of::<VirtioNimbleReqCreateSegment>() {
            return Err(Error::InvalidRequest);
        }

        let req: VirtioNimbleReqCreateSegment = desc_chain
            .memory()
            .read_obj(req_addr as GuestAddress)
            .map_err(Error::GuestMemory)?;

        let name_cstr = unsafe { std::ffi::CStr::from_ptr(req.name.as_ptr()) };
        let str_slice = name_cstr.to_str().map_err(Error::StringConversion)?;

        let mut sm = self.segment_manager.lock().map_err(|e|{Error::BackendLock { error: e.to_string() }})?;
        if !sm.initialized() {
            return Err(Error::SegmentManagerInitialization)
        }
        let region = sm.create_region(str_slice, req.size)?;
        if region.size != req.size {
            return Err(Error::SegmentTooLarge);
        }
        let resp = VirtioNimbleRespCreate {
            offset: region.offset,
        };
        response.extend_from_slice(resp.as_slice());

        Ok(response)
    }

    fn process_queue(
        &mut self,
        vring: &mut RwLockWriteGuard<VringState<GuestMemoryAtomic<GuestMemoryMmap>>>,
    ) -> bool {
        let mut used_descs = false;

        while let Some(mut desc_chain) = vring
            .get_queue_mut()
            .pop_descriptor_chain(self.mem.memory())
        {
            debug!("got an element in the queue");
            let len: usize = match self.handle(&mut desc_chain) {
                Ok(written) => { written }
                Err(err) => {
                    error!("failed to parse available descriptor chain: {:?}", err);
                    0
                }
            };

            let len32 : u32 = len.try_into().unwrap();

            vring
                .get_queue_mut()
                .add_used(desc_chain.memory(), desc_chain.head_index(), len32)
                .unwrap();
            used_descs = true;
        }

        let mut needs_signalling = false;
        if self.event_idx {
            if vring
                .get_queue_mut()
                .needs_notification(self.mem.memory().deref())
                .unwrap()
            {
                debug!("signalling queue");
                needs_signalling = true;
            } else {
                debug!("omitting signal (event_idx)");
            }
        } else {
            debug!("signalling queue");
            needs_signalling = true;
        }

        if needs_signalling {
            vring.signal_used_queue().unwrap();
        }

        used_descs
    }
}

pub struct VhostUserNimbleNetBackend {
    threads: Vec<Mutex<VhostUserNimbleNetThread>>,
    num_queues: usize,
    queue_size: u16,
    queues_per_thread: Vec<u64>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
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
        let segment_manager = Arc::new(Mutex::new(ShmemManager::new(mem.clone(), size)));
        let thread = Mutex::new(VhostUserNimbleNetThread::new(mem.clone(), segment_manager)?);
        threads.push(thread);
        queues_per_thread.push(0b1);

        Ok(VhostUserNimbleNetBackend {
            threads,
            num_queues,
            queue_size,
            queues_per_thread,
            mem,
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

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>],
        thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut thread = self.threads[thread_id].lock().unwrap();
        match device_event {
            0 => {
                let mut vring = vrings[0].get_mut();
                // \TODO consider polling the queue
                 if thread.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring
                            .get_queue_mut()
                            .enable_notification(self.mem.memory().deref())
                            .unwrap();
                        if !thread.process_queue(&mut vring) {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    thread.process_queue(&mut vring);
                }

                Ok(false)
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

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
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> VhostUserBackendResult<()> {
        self.mem = mem;
        Ok(())
    }

    fn set_event_idx(&mut self, _enabled: bool) {}
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
