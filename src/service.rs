use std::{time::Duration, error::Error, sync::{Arc, Mutex}, collections::HashMap, marker::PhantomData};

use dbus::{nonblock::{self, SyncConnection}, arg::{PropMap, Variant}, Path, channel::MatchingReceiver, message::MatchRule, MethodErr};
use dbus_crossroads::Crossroads;
use futures::future;
use log::{debug, info};
use tokio::task::AbortHandle;

use crate::{error::PassNMError, minipass::{delete_passwd, read_passwd, write_passwd}, network_manager::{NetworkConnection, NetworkSecurity}};

pub const PASS_DIR: &str = "network";

const SECRET_AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";

pub type PropMapMap = HashMap<String, PropMap>;
type ConnectionHandleMap = HashMap<(String, String), AbortHandle>;

fn invalid_arg<T>(err: &str) -> Result<T, MethodErr> {
    Err(MethodErr::invalid_arg(err))
}

pub async fn delete_stored_secrets(id: &str, security: &NetworkSecurity) -> Result<(), PassNMError> {
    match security {
        NetworkSecurity::WpaPsk { psk: _, flags: _ } => {
            // Delete the psk
            delete_passwd(PASS_DIR, &format!("{}.wpa-psk", id))
                .await?;
            Ok(())
        }
    }
}

// insert password into password storage
pub async fn save_secrets(id: &str, security: &NetworkSecurity) -> Result<(), PassNMError> {
    match security {
        NetworkSecurity::WpaPsk { psk: Some(psk), flags: _ } => {
            // Write the psk
            write_passwd(PASS_DIR, &format!("{}.wpa-psk", id), &psk)
                .await?;

            Ok(())
        },
        _ => Err(PassNMError::InvalidSecurity)
    }
}

// Handle a request for secrets for a given network and setting name
// Returns a secret response object
async fn handle_secrets_request<'a>(network: Option<NetworkConnection<'a>>, setting_name: String, allow_interaction: bool) -> Result<(PropMapMap, ), MethodErr> {
    debug!("handling request for {} for network {:?}", setting_name, network);

    match network {
        Some(NetworkConnection { id, security: Some(security), .. }) => {
            // Current response item
            let mut response_item = PropMap::new();
            
            match (setting_name.as_str(), security) {
                // 802-11 with WPA-PSK and an agent-managed psk
                ("802-11-wireless-security", NetworkSecurity::WpaPsk { psk: _, flags: 0x1 }) => {
                    // Look the psk up
                    match read_passwd(PASS_DIR, &format!("{}.wpa-psk", id), allow_interaction).await {
                        Ok(psk) => {
                            // Add the psk
                            response_item.insert("psk".into(), Variant(Box::new(psk)));
                        },
                        Err(err) => {
                            return Err(MethodErr::failed(&err));
                        }
                    }
                },
                _ => return invalid_arg("unsupported network security")
            };

            // Set up the response
            let mut response = PropMapMap::new();
            response.insert(setting_name.into(), response_item);
            Ok((response, ))
        },
        Some(NetworkConnection { .. }) => invalid_arg("network does not have security"),
        _ => invalid_arg("invalid network")
    }
}

// Add a new req handler (optionally) to the handle map mutex and cancel existing ones
fn add_new_req_handler(cr: &mut Crossroads, path: Path, setting_name: String, abort_handle: Option<AbortHandle>) {
    let map_key = (path.to_string(), setting_name);
    let handle_map: &mut ConnectionHandleMap = cr.data_mut(&Path::new(SECRET_AGENT_PATH).unwrap()).unwrap();

    // If we got an actual new abort handle, insert it, otherwise just remove the old one
    if let Some(old_handle) = match abort_handle { Some(h) => handle_map.insert(map_key, h), None => handle_map.remove(&map_key) } {
        old_handle.abort();
    }
}

pub async fn run_service(conn: Arc<SyncConnection>) -> Result<(), Box<dyn Error>> {
    // First register our service
    let nm_proxy = nonblock::Proxy::new("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/AgentManager", Duration::from_secs(2), conn.clone());
    nm_proxy.method_call("org.freedesktop.NetworkManager.AgentManager", "Register", ("grimsteel.pass-nm-agent",)).await?;
    info!("Registered network manager agent");

    //conn.request_name("com.grimsteel.passnmagent", false, true, false).await?;

    let cr = Arc::new(Mutex::new(Crossroads::new()));

    {
        let mut cr_lock = cr.lock().unwrap();
        let conn = conn.clone();

        // Enable async support
        cr_lock.set_async_support(Some((conn.clone(), Box::new(|fut| { tokio::spawn(fut); } ))));

        let iface_token = cr_lock.register("org.freedesktop.NetworkManager.SecretAgent", |builder| {
            // Get secrets from pass
            builder.method_with_cr_async(
                "GetSecrets",
                ("connection", "connection_path", "setting_name", "hints", "flags"),
                ("secrets",),
                move |mut ctx, cr, (connection, connection_path, setting_name, _hints, flags): (PropMapMap, Path, String, Vec<String>, u32)| {
                    info!("GetSecrets: {} for {}", setting_name, connection_path);
                    
                    // Allow interaction if 0b1 (allow interaction) or 0b10 (prompt for new) is set
                    let allow_interaction = (flags & 0b11) > 0;

                    let network = NetworkConnection::try_from((connection_path.clone(), connection));
                        let handle = tokio::spawn(handle_secrets_request(network.ok(), setting_name.clone(), allow_interaction));

                        // Cancel existing requests
                        add_new_req_handler(cr, connection_path, setting_name, Some(handle.abort_handle()));

                        async move {
                            if let Ok(data) = handle.await {
                                ctx.reply(data)
                            } else {
                                // No response
                                PhantomData
                            }
                        }
                    

                }
            );

            builder.method_with_cr_async(
                "CancelGetSecrets",
                ("connection_path", "setting_name"),
                (),
                move |mut ctx, cr, (connection_path, setting_name): (Path, String)| {
                    info!("CancelGetSecrets: {} for {}", setting_name, connection_path);
                    
                    // Just cancel existing reqs
                    add_new_req_handler(cr, connection_path, setting_name, None);
                    
                    async move {
                        ctx.reply(Ok(()))
                    }
                }
            );

            builder.method_with_cr_async(
                "DeleteSecrets",
                ("connection", "connection_path"),
                (),
                |mut ctx, _cr, (connection, connection_path): (PropMapMap, Path)| {
                    info!("DeleteSecrets: for {}", connection_path);
                    async move {
                        ctx.reply(match (connection_path, connection).try_into() {
                            // NetworkConnection with security
                            Ok(NetworkConnection { id, security: Some(security), .. }) => delete_stored_secrets(&id, &security).await.map_err(|e| MethodErr::failed(&e)),
                            // any other NetworkConnection
                            Ok(_network) => Err(MethodErr::invalid_arg("network does not use secrets")),
                            // Error
                            Err(e) => Err(MethodErr::invalid_arg(&e))
                        })
                    }
                }
            );

            builder.method_with_cr_async(
                "SaveSecrets",
                ("connection", "connection_path"),
                (),
                |mut ctx, _cr, (connection, connection_path): (PropMapMap, Path)| {
                    info!("SaveSecrets: for {}", connection_path);
                    async move {
                        ctx.reply(match (connection_path, connection).try_into() {
                            // NetworkConnection with security
                            Ok(NetworkConnection { id, security: Some(security), .. }) => save_secrets(&id, &security).await.map_err(|e| MethodErr::failed(&e)),
                            // any other NetworkConnection
                            Ok(_network) => Err(MethodErr::invalid_arg("network does not use secrets")),
                            // Error
                            Err(e) => Err(MethodErr::invalid_arg(&e))
                        })
                    }
                }
            );
        });

        // Set up the SecretAgent path with an empty connectio handle map
        cr_lock.insert(SECRET_AGENT_PATH, &[iface_token], ConnectionHandleMap::new());
    }

    // Start listening
    conn.start_receive(MatchRule::new_method_call(), Box::new(move |msg, conn| {
        cr.lock().unwrap().handle_message(msg, conn).unwrap();
        true
    }));

    // Just run forever
    future::pending::<()>().await;
    unreachable!();
}
