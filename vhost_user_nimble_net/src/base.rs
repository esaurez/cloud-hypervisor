use ::core::ops::{
        Deref,
        DerefMut,
    };
use std::{io, slice};

use option_parser::OptionParserError;
use vm_memory::{GuestMemoryError, GuestMemoryAtomic, GuestAddress, bitmap::AtomicBitmap, GuestAddressSpace, GuestMemory, GuestMemoryRegion, GuestMemoryLoadGuard};

pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to create kill eventfd: {0}")]
    CreateKillEventFd(io::Error),
    #[error("Failed to parse configuration string: {0}")]
    FailedConfigParse(OptionParserError),
    #[error("Failed to signal used queue: {0}")]
    FailedSignalingUsedQueue(io::Error),
    #[error("Failed to handle event other than input event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknownEvent,
    #[error("No socket provided")]
    SocketParameterMissing,
    #[error("Missing size")]
    SizeParameterMissing,
    #[error("Guest gave us too few descriptors in a descriptor chain")]
    DescriptorChainTooShort,
    #[error("Read type of request was invalid")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Format of the request was invalid")]
    InvalidRequest,
    #[error("Failed to read from guest memory: {0}")]
    GuestMemory(GuestMemoryError),
    #[error("Failed getting memory guard")]
    MemoryGuard,
    #[error("Region not found")]
    RegionNotFound,
    #[error("Region size is not correct {0}, expected {1}")]
    RegionSizeInvalid(u64, u64),
    #[error("Region start address is not correct {0}, expected {1}")]
    RegionAddressInvalid(u64, u64),
    #[error("Address was not found in region")]
    InvalidRegionAddr,
    #[error("Segment is too large for the region in which it is being created")]
    SegmentTooLarge,
    #[error("Error locking the backend {error:?}")]
    BackendLock { error: String },
    #[error("Error retrieving the segment")]
    SegmentRetrieval,
    #[error("Segment manager is not initialized")]
    SegmentManagerInitialization,
    #[error("Error converting a C string into a rust string")]
    StringConversion(std::str::Utf8Error),
    #[error("Integer conversion (downgrade) failed")]
    IntegerConversion(std::num::TryFromIntError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Segment {
    pub offset: u64,
    pub size: u64,
}

impl Clone for Segment {
    fn clone(&self) -> Self {
        Segment {
            offset: self.offset,
            size: self.size,
        }
    }    
}

pub struct MemGuard {
    addr: *mut u8,
    size: u64,
}

impl MemGuard {
    pub fn new(mem_guard: &GuestMemoryLoadGuard<GuestMemoryMmap>, gpa: GuestAddress) -> Result<MemGuard> {
        let region = mem_guard.find_region(gpa).ok_or(Error::RegionNotFound)?;
        Ok(
            MemGuard {
                addr: region.as_ptr(),
                size: region.len(),
            }
        )
    }
}

pub struct SharedMemory {
    // Mem and mem_snapshot contain the backing data for mem_guard
    _mem: GuestMemoryAtomic<GuestMemoryMmap>,
    _mem_snapshot: GuestMemoryLoadGuard<GuestMemoryMmap>,
    // mem_guard should never be copied out from Shared Memory, as it depends on the data of _mem_snapshot
    mem_guard: MemGuard, 
    offset: usize,
    size: usize,

}

pub trait SegmentsManager : Send {
    fn create_region(&mut self, segment_name: &str, segment_size: u64) -> Result<Segment>;
    fn get_region(&mut self, segment_name: &str) -> Result<Segment>;
    fn mmap_region(&mut self, segment: &Segment) -> Result<SharedMemory>;
}

impl SharedMemory {
    pub fn new(
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        gpa: GuestAddress,
        offset: usize,
        size: usize,
    ) -> Result<SharedMemory> {
        //\TODO update the region ref, when address are changed (e.g., after migration)
        let mem_snapshot = mem.memory();
        let mem_guard = MemGuard::new(&mem_snapshot, gpa)?;
        Ok(SharedMemory {
            _mem: mem,
            _mem_snapshot: mem_snapshot,
            mem_guard,
            offset,
            size
        })
    }
}

impl Deref for SharedMemory {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let slice = unsafe { slice::from_raw_parts(self.mem_guard.addr, self.mem_guard.size as usize) };
        &slice[self.offset..self.offset+self.size]
    }
}

impl<'a> DerefMut for SharedMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let slice = unsafe { slice::from_raw_parts_mut(self.mem_guard.addr, self.mem_guard.size as usize) };
        &mut slice[self.offset..self.offset+self.size]
    }
}