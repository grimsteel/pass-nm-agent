mod minipass;
mod service;
mod cli;
mod network_manager;
mod error;

use std::{error::Error, process::exit, sync::Arc};

use cli::{delete_network, insert_network};
use dbus::nonblock::SyncConnection;
use dbus_tokio::connection;
use service::run_service;
use log::error;

const HELP: &str = "USAGE:
  pass-nm-agent <COMMAND> [OPTIONS]

OPTIONS:
  -h, --help   Print help

COMMANDS:
  agent   Start the `network manager` agent
  add     Move a wifi password from `network manager` to `pass`
  remove  Remove a wifi password from `pass`
";

const ADD_HELP: &str = "Move a wifi password from `network manager` to `pass`

USAGE:
  pass-nm-agent add [OPTIONS] <NETWORK>

ARGUMENTS:
  <NETWORK>  The wifi network name

OPTIONS:
  -h, --help   Print help
  -f, --force  Overwrite existing wifi password in `pass`
";

const REMOVE_HELP: &str = "Remove a wifi password from `pass`

USAGE:
  pass-nm-agent remove [OPTIONS] <NETWORK>

ARGUMENTS:
  <NETWORK>  The wifi network name

OPTIONS:
  -h, --help  Print help
";

fn init_connection() -> Result<Arc<SyncConnection>, dbus::Error> {
    // Start a D-Bus session
    let (resource, conn) = connection::new_system_sync()?;

    // Resource
    let _resource_handle = tokio::spawn(async {
        let err = resource.await;
        // If it finished, we lost connection
        panic!("Lost connection to D-Bus: {}", err);
    });
    
    Ok(conn)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    
    let mut args = pico_args::Arguments::from_env();

    let has_help = args.contains(["-h", "--help"]);

    let command = args.subcommand()?;

    match command.as_deref() {
        Some("agent") => {
            let conn = init_connection()?;
            run_service(conn).await?;
        },
        Some("add") => {
            if has_help {
                print!("{}", ADD_HELP);
                exit(0);
            }
            let conn = init_connection()?;
            let network: String = args.free_from_str()?;
            // add
            insert_network(conn, &network).await?;
        },
        Some("remove") => {
            if has_help {
                print!("{}", REMOVE_HELP);
                exit(0);
            }
            let conn = init_connection()?;
            let network: String = args.free_from_str()?;
            // remove
            delete_network(conn, &network).await?;
        },
        _ => {
            if has_help {
                print!("{}", HELP);
                exit(0);
            } else {
                error!("{}", HELP);
                // non zero exit code if it was run without --help
                exit(1);
            }
        }
    }

    Ok(())
}
