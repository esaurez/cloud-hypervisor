// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use super::{Error, Result, DEFAULT_VIRTIO_FEATURES};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::vhost_user::VhostUserCommon;
use crate::{
    ActivateResult, UserspaceMapping, VirtioCommon, VirtioDevice,
    VirtioInterrupt, VirtioSharedMemoryList, VIRTIO_F_IOMMU_PLATFORM,
};
use crate::{GuestMemoryMmap, GuestRegionMmap};
use seccompiler::SeccompAction;
use vm_virtio::VirtioDeviceType;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{
    MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler,
};
use virtio_queue::Queue;
use vm_memory::{GuestAddress, GuestMemoryAtomic};
use vm_migration::{
    protocol::MemoryRangeTable, Migratable, MigratableError, Pausable, Snapshot, Snapshottable,
    Transportable, VersionMapped,
};
use vmm_sys_util::eventfd::EventFd;

const DEFAULT_QUEUE_NUMBER: usize = 1;

#[derive(Versionize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub vu_num_queues: usize,
}

impl VersionMapped for State {}


struct FrontendReqHandler {}

impl VhostUserMasterReqHandler for FrontendReqHandler {}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct VirtioNimbleNetConfig {}

pub struct NimbleNet {
    common: VirtioCommon,
    vu_common: VhostUserCommon,
    id: String,
    seccomp_action: SeccompAction,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    epoll_thread: Option<thread::JoinHandle<()>>,
    exit_evt: EventFd,
    iommu: bool,
    virtio_shm_list: VirtioSharedMemoryList,
}

impl NimbleNet {
    /// Create a new virtio-fs device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        virtio_shm_list: VirtioSharedMemoryList,
        vu_cfg: VhostUserConfig,
        server: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        iommu: bool,
        state: Option<State>,
    ) -> Result<NimbleNet> {

        let num_queues = vu_cfg.num_queues;

        let mut vu =
            VhostUserHandle::connect_vhost_user(server, &vu_cfg.socket, num_queues as u64, false)?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            paused,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-nimble-net {}", id);

            vu.set_protocol_features_vhost_user(
                state.acked_features,
                state.acked_protocol_features,
            )?;

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                true,
            )
        } else {
            // Filling device and vring features VMM supports.
            let avail_features = DEFAULT_VIRTIO_FEATURES;

            let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD;

            let (acked_features, acked_protocol_features) =
                vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

            let backend_num_queues =
                if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                    vu.socket_handle()
                        .get_queue_num()
                        .map_err(Error::VhostUserGetQueueMaxNum)? as usize
                } else {
                    DEFAULT_QUEUE_NUMBER
                };

            if num_queues > backend_num_queues {
                error!(
                "vhost-user-nimble-net requested too many queues ({}) since the backend only supports {}\n",
                num_queues, backend_num_queues
            );
                return Err(Error::BadQueueNum);
            }

            (
                acked_features,
                // If part of the available features that have been acked, the
                // PROTOCOL_FEATURES bit must be already set through the VIRTIO
                // acked features as we know the guest would never ack it, thus
                // the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                num_queues,
                false,
            )
        };

        Ok(NimbleNet {
            common: VirtioCommon {
                device_type: VirtioDeviceType::NimbleNet as u32,
                queue_sizes: vec![vu_cfg.queue_size; num_queues],
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: DEFAULT_QUEUE_NUMBER as u16,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            vu_common: VhostUserCommon {
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: vu_cfg.socket,
                vu_num_queues,
                ..Default::default()
            },
            id,
            seccomp_action,
            guest_memory: None,
            epoll_thread: None,
            exit_evt,
            iommu,
            virtio_shm_list
        })
    }

    

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            acked_protocol_features: self.vu_common.acked_protocol_features,
            vu_num_queues: self.vu_common.vu_num_queues,
        }
    }
}

impl Drop for NimbleNet {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
        if let Some(thread) = self.epoll_thread.take() {
            if let Err(e) = thread.join() {
                error!("Error joining thread: {:?}", e);
            }
        }
    }
}

impl VirtioDevice for NimbleNet {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        let mut features = self.common.avail_features;
        if self.iommu {
            features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }
        features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        // write all zeros as we don't have any config
        data.fill_with(Default::default);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, &interrupt_cb)?;
        self.guest_memory = Some(mem.clone());

        // Initialize slave communication.
        let master_req_handler: Option<MasterReqHandler<FrontendReqHandler>> = None;

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler = self.vu_common.activate(
            mem,
            queues,
            interrupt_cb,
            self.common.acked_features,
            master_req_handler,
            kill_evt,
            pause_evt,
        )?;
        
        //\TODO may need to add a thread for the control queues here

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        let mut epoll_threads = Vec::new();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostNimbleNet,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(paused, paused_sync.unwrap()),
        )?;
        self.epoll_thread = Some(epoll_threads.remove(0));

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(vu) = &self.vu_common.vu {
            if let Err(e) = vu.lock().unwrap().reset_vhost_user() {
                error!("Failed to reset vhost-user daemon: {:?}", e);
                return None;
            }
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown()
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        Some(self.virtio_shm_list.clone())
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        self.virtio_shm_list = shm_regions;
        Ok(())
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(&self.guest_memory, region)
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        let mut mappings = Vec::new();
        let shm_list: &VirtioSharedMemoryList = &self.virtio_shm_list;
        if shm_list.addr == GuestAddress(0) || shm_list.mem_slot == std::u32::MAX {
            return mappings;
        }
        mappings.push(UserspaceMapping {
            host_addr: shm_list.host_addr,
            mem_slot: shm_list.mem_slot,
            addr: shm_list.addr,
            len: shm_list.len,
            mergeable: false,
        });

        mappings
    }
}

impl Pausable for NimbleNet {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }

        self.vu_common.resume()
    }
}

impl Snapshottable for NimbleNet {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state())
    }
}
impl Transportable for NimbleNet {}

impl Migratable for NimbleNet {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log(&self.guest_memory)
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log(&self.guest_memory)
    }

    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.start_migration()
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common
            .complete_migration(self.common.kill_evt.take())
    }
}
