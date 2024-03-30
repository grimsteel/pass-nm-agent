mod minipass;
mod service;
mod cli;

use std::{error::Error, process::exit};

use cli::{delete_network, insert_network};
use dbus_tokio::connection;
use service::run_service;

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

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = pico_args::Arguments::from_env();

    let has_help = args.contains(["-h", "--help"]);

    let command = args.subcommand()?;

    // Start a D-Bus session
    let (resource, conn) = connection::new_system_sync()?;
    println!("Name on D-Bus: {}", conn.unique_name().to_string());

    // Resource
    let _resource_handle = tokio::spawn(async {
        let err = resource.await;
        // If it finished, we lost connection
        panic!("Lost connection to D-Bus: {}", err);
    });

    match command.as_deref() {
        Some("agent") => {
            run_service(conn).await?;
        },
        Some("add") => {
            if has_help {
                print!("{}", ADD_HELP);
                exit(0);
            }
            let network: String = args.free_from_str()?;
            // add
            insert_network(conn, &network).await?;
        },
        Some("remove") => {
            if has_help {
                print!("{}", REMOVE_HELP);
                exit(0);
            }
            let network: String = args.free_from_str()?;
            // remove
            delete_network(conn, &network).await?;
        },
        _ => {
            print!("{}", HELP);
            if has_help {
                exit(0);
            } else {
                // non zero exit code if it was run without --help
                exit(1);
            }
        }
    }

    Ok(())
}
