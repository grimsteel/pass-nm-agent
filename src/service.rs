use std::{time::Duration, error::Error, sync::{Arc, Mutex}, collections::HashMap, marker::PhantomData};

use dbus::{arg::{PropMap, RefArg, Variant}, channel::MatchingReceiver, message::MatchRule, nonblock::{self, SyncConnection}, MethodErr, Path};
use dbus_crossroads::Crossroads;
use futures::future;
use log::{debug, info};
use tokio::task::AbortHandle;

use crate::{b64url::to_base64url, error::PassNMError, minipass::{delete_passwd, read_passwd, write_passwd}, model::{NetworkConnection, NetworkSecurity, PwWithFlags}};

pub const PASS_DIR: &str = "network";

const SECRET_AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";

pub type PropMapMap = HashMap<String, PropMap>;
type ConnectionHandleMap = HashMap<(String, String), AbortHandle>;

fn invalid_arg<T>(err: &str) -> Result<T, MethodErr> {
    Err(MethodErr::invalid_arg(err))
}

pub async fn delete_stored_secrets(id: &str, security: &NetworkSecurity) -> Result<(), PassNMError> {
    match security {
        NetworkSecurity::WpaPsk(..) => {
            // Delete the psk
            delete_passwd(PASS_DIR, &format!("{}.wpa-psk", id))
                .await?;
            Ok(())
        },
        NetworkSecurity::WpaEap { client_cert_pw, private_key_pw, password } => {
            // Delete the password
            if password.flags == 0x1 {
                delete_passwd(PASS_DIR, &format!("{}.wpa-eap-password", id)).await?;
            }
            // Delete the client cert pw
            if client_cert_pw.flags == 0x1 {
                delete_passwd(PASS_DIR, &format!("{}.wpa-eap-client-cert-password", id)).await?;
            }
            // Delete the private key pw
            if private_key_pw.flags == 0x1 {
                delete_passwd(PASS_DIR, &format!("{}.wpa-eap-private-key-password", id)).await?;
            }
            Ok(())
        },
        NetworkSecurity::Wireguard { private_key, peer_psks } => {
            // Delete the privkey
            if private_key.flags == 0x1 {
                delete_passwd(PASS_DIR, &format!("{}.wg-private-key", id)).await?;
            }
            // Delete all peer psks
            for (pubkey, psk) in peer_psks {
                if psk.flags == 0x1 {
                    delete_passwd(PASS_DIR, &format!("{}.{}.wg-preshared-key", id, to_base64url(pubkey))).await?;
                }
            }

            Ok(())
        }
    }
}

// insert password into password storage
pub async fn save_secrets(id: &str, security: &NetworkSecurity) -> Result<(), PassNMError> {
    match security {
        NetworkSecurity::WpaPsk(PwWithFlags{ pw: Some(psk), .. }) => {
            // Write the psk
            write_passwd(PASS_DIR, &format!("{}.wpa-psk", id), &psk)
                .await?;

            Ok(())
        },
        NetworkSecurity::WpaEap { client_cert_pw, private_key_pw, password } => {
            if let Some(password) = &password.pw {
                write_passwd(PASS_DIR, &format!("{}.wpa-eap-password", id), &password).await?;
            }
            if let Some(password) = &client_cert_pw.pw {
                write_passwd(PASS_DIR, &format!("{}.wpa-eap-client-cert-password", id), &password).await?;
            }
            if let Some(password) = &private_key_pw.pw {
                write_passwd(PASS_DIR, &format!("{}.wpa-eap-private-key-password", id), &password).await?;
            }
            Ok(())
        },
        NetworkSecurity::Wireguard { private_key, peer_psks } => {
            if let Some(private_key) = &private_key.pw {
                write_passwd(PASS_DIR, &format!("{}.wg-private-key", id), &private_key).await?;
            }
            // all peer psks
            for (pubkey, psk) in peer_psks {
                if let Some(psk) = &psk.pw {
                    write_passwd(PASS_DIR, &format!("{}.{}.wg-preshared-key", id, to_base64url(pubkey)), &psk).await?;
                }
            }
            Ok(())
        },
        _ => Err(PassNMError::InvalidSecurity)
    }
}

async fn read_single_secret(network_id: &str, secret_ext: &str, secret_field: &str, allow_interaction: bool, response_item: &mut PropMap) -> Result<(), MethodErr> {
    match read_passwd(PASS_DIR, &format!("{}.{}", network_id, secret_ext), allow_interaction).await {
         Ok(password) => {
             // Add the password
             response_item.insert(secret_field.into(), Variant(Box::new(password)));
         },
         Err(err) => {
             return Err(MethodErr::failed(&err));
         }
    }

    Ok(())
}

// Handle a request for secrets for a given network and setting name
// Returns a secret response object
async fn handle_secrets_request<'a>(network: Option<NetworkConnection<'a>>, setting_name: String, allow_interaction: bool) -> Result<(PropMapMap, ), MethodErr> {
    debug!("handling request for {} for network {:?}", setting_name, network);

    match network {
        Some(NetworkConnection { id, security: Some(security), .. }) => {
            // Make sure the setting name matches the security
            if setting_name != security.get_secret_setting_name() {
                return invalid_arg("setting name does not match security");
            }
                
            // Current response item
            let mut response_item = PropMap::new();
            
            match security {
                // 802-11 with WPA-PSK and an agent-managed psk
                NetworkSecurity::WpaPsk(PwWithFlags { flags: 0x1, .. }) => {
                    // Look the psk up
                    read_single_secret(&id, "wpa-psk", "psk", allow_interaction, &mut response_item).await?;
                },
                // 802-1x
                NetworkSecurity::WpaEap { client_cert_pw, private_key_pw, password } => {
                    // Handle all agent managed items
                    if client_cert_pw.flags == 0x1 {
                        read_single_secret(&id, "wpa-eap-client-cert-password", "client-cert-password", allow_interaction, &mut response_item).await?;
                    }
                    if private_key_pw.flags == 0x1 {
                        read_single_secret(&id, "wpa-eap-private-key-password", "private-key-password", allow_interaction, &mut response_item).await?;
                    }
                    if password.flags == 0x1 {
                        read_single_secret(&id, "wpa-eap-password", "password", allow_interaction, &mut response_item).await?;
                    }
                },
                NetworkSecurity::Wireguard { private_key, peer_psks } => {
                    debug!("{:#?} {:#?}", private_key, peer_psks);
                    if private_key.flags == 0x1 {
                        read_single_secret(&id, "wg-private-key", "private-key", allow_interaction, &mut response_item).await?;
                    }

                    // Handle psks
                    let mut peers: Vec<PropMap> = Vec::with_capacity(peer_psks.len());
                    for (pubkey, psk) in peer_psks {
                        if psk.flags == 0x1 {
                            let mut map = PropMap::new();
                            if read_single_secret(&id, &format!("{}.wg-preshared-key", to_base64url(&pubkey)), "preshared-key", allow_interaction, &mut map).await.is_ok() {
                                // Add this peer to our peers list
                                map.insert("public-key".into(), Variant(Box::new(pubkey)));
                                peers.push(map);
                            }
                        } 
                    }

                    response_item.insert("peers".into(), Variant(Box::new(peers) as Box<dyn RefArg>));
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
