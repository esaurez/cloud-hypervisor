// Copyright 2023 Microsoft Corporation. All Rights Reserved.

use argh::FromArgs;
use vhost_user_nimble_net::start_nimble_net_backend;

#[derive(FromArgs)]
/// Launch a vhost-user-nimble-net backend.
struct TopLevel {
    #[argh(option, long = "nimble-net-backend")]
    /// vhost-user-nimble-net backend parameters
    /// size=<shmem_size>,socket=<socket_path>,client=on|off,num_queues=<number_of_queues>,queue_size=<size_of_each_queue>
    backend_command: Option<String>,

    #[argh(switch, short = 'V', long = "version")]
    /// print version information
    version: bool,
}

fn main() {
    env_logger::init();

    let toplevel: TopLevel = argh::from_env();

    if toplevel.version {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("BUILT_VERSION"));
        return;
    }

    if toplevel.backend_command.is_none() {
        println!("Please specify --nimble-net-backend");
        std::process::exit(1)
    }

    start_nimble_net_backend(&toplevel.backend_command.unwrap());
}
