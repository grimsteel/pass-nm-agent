use std::{time::Duration, error::Error, sync::{Arc, Mutex}, collections::HashMap, marker::PhantomData};

use dbus::{nonblock::{self, SyncConnection}, arg::{PropMap, RefArg, Variant}, Path, channel::MatchingReceiver, message::MatchRule, MethodErr};
use dbus_crossroads::Crossroads;
use futures::future;
use tokio::task::AbortHandle;

use crate::minipass::{read_passwd, delete_passwd, write_passwd};

pub const PASS_DIR: &str = "wifi";
pub const WIFI_SETTING_NAME: &str = "802-11-wireless-security";

pub type PropMapMap = HashMap<String, PropMap>;
type ConnectionHandleMap = HashMap<(String, String), AbortHandle>;

fn invalid_arg<T>(err: &str) -> Result<T, MethodErr> {
    Err(MethodErr::invalid_arg(err))
}

// Returns ssid, key_mgmt, req_new, allow_interaction
pub fn parse_connection_data<'a>(connection: &'a PropMapMap) -> Option<(&'a str, &'a str)> {
    let ssid = connection.get("connection").and_then(|c| c.get("id")).and_then(|i| i.as_str());
    let setting_data = connection.get(WIFI_SETTING_NAME);
    // this indicates what type of wifi authentication (WPA-PSK, WPA-EAP, etc) the network uses
    let key_mgmt = setting_data.and_then(|s| s.get("key-mgmt")).and_then(|i| i.as_str());

    if let (Some(ssid), Some(key_mgmt)) = (ssid, key_mgmt) {
        Some((ssid, key_mgmt))
    } else {
        None
    }
}

pub async fn delete_passwd_from_connection(connection: &PropMapMap) -> Result<(), String> {
    if let Some((ssid, key_mgmt)) = parse_connection_data(connection) {
        delete_passwd(PASS_DIR, &format!("{}.{}", ssid, key_mgmt)).await?;
        Ok(())
    } else {
        Err("invalid connection data".to_string())
    }
}

// insert password into password storage and remove from `connection`
async fn insert_passwd_from_connection(connection: &mut PropMapMap) -> Result<(), String> {
    if let Some((ssid, key_mgmt)) = parse_connection_data(connection) {
        match key_mgmt {
            "wpa-psk" => {
                let passwd_id = format!("{}.wpa-psk", ssid);
                let wifi_settings = connection.get_mut(WIFI_SETTING_NAME).unwrap();
                let psk = wifi_settings.get("psk").and_then(|i| i.as_str()).ok_or_else(|| "psk field does not exist")?;
                write_passwd(PASS_DIR, &passwd_id, psk).await.map_err(|_| "could not store password")?;
                // remove the password from `connection`
                //wifi_settings.remove("psk");
                //wifi_settings.insert("psk-flags".to_string(), Variant(Box::new(1 as u32)));
                Ok(())
            },
            _ => Err("unsupported wifi key mgmt".to_string())
        }
    } else {
        Err("invalid connection data".to_string())
    }
}

async fn handle_wifi_request(ssid: String, key_mgmt: String, allow_interaction: bool) -> Result<(PropMapMap, ), MethodErr> {
    match key_mgmt.as_ref() {
        "wpa-psk" => {
            // now lookup the password
            let key_id = format!("{}.wpa-psk", ssid);
            match read_passwd(PASS_DIR, &key_id, allow_interaction).await {
                Ok(password) => {
                    // prepare the response hash map
                    let mut response: HashMap<String, PropMap> = HashMap::new();
                    let mut response_wifi = PropMap::new();
                    response_wifi.insert("psk".to_string(), Variant(Box::new(password)));
                    response.insert(WIFI_SETTING_NAME.to_string(), response_wifi);
                    Ok((response, ))
                },
                Err(err) => {
                    Err(MethodErr::failed(&err))
                }
            }
        },
        _ => {
            // Unsupported wifi key management
            invalid_arg("unsupported wifi key mgmt")
        }
    }
}

pub async fn run_service(conn: Arc<SyncConnection>) -> Result<(), Box<dyn Error>> {
    // First register our service
    let nm_proxy = nonblock::Proxy::new("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/AgentManager", Duration::from_secs(2), conn.clone());
    nm_proxy.method_call("org.freedesktop.NetworkManager.AgentManager", "Register", ("grimsteel.pass-nm-agent",)).await?;
    println!("Registered network manager agent");

    //conn.request_name("com.grimsteel.passnmagent", false, true, false).await?;

    let cr = Arc::new(Mutex::new(Crossroads::new()));

    {
        let mut cr_lock = cr.lock().unwrap();
        let cr2 = cr.clone();
        let cr3 = cr.clone();
        let conn = conn.clone();

        // Enable async support
        cr_lock.set_async_support(Some((conn.clone(), Box::new(|fut| { tokio::spawn(fut); } ))));

        let iface_token = cr_lock.register("org.freedesktop.NetworkManager.SecretAgent", |builder| {
            //let existing_reqs = existing_reqs.clone();
            builder.method_with_cr_async(
                "GetSecrets",
                ("connection", "connection_path", "setting_name", "hints", "flags"),
                ("secrets",),
                move |mut ctx, _cr, (connection, _connection_path, setting_name, _hints, flags): (PropMapMap, Path, String, Vec<String>, u32)| {
                    let cr = cr2.clone();
                    async move {
                        // We only support wifi
                        if setting_name == WIFI_SETTING_NAME {
                            let req_new = flags & 0x2 == 0x2;
                            let allow_interaction = req_new || flags & 0x1 == 0x1;
                            if let Some((ssid, key_mgmt)) = parse_connection_data(&connection) {
                                let handle = tokio::spawn(handle_wifi_request(ssid.to_string(), key_mgmt.to_string(), allow_interaction));

                                {
                                    // Cancel any existing tasks (network manager should NOT let this ever happen)
                                    let mut cr_lock = cr.lock().unwrap();
                                    let map_key = (ssid.to_string(), key_mgmt.to_string());
                                    let existing_reqs: &mut ConnectionHandleMap = cr_lock.data_mut(ctx.path()).unwrap();
                                    if let Some(abort_handle) = existing_reqs.remove(&map_key) {
                                        abort_handle.abort();
                                    }
                                
                                    existing_reqs.insert(map_key, handle.abort_handle());
                                }
                                
                                if let Ok(data) = handle.await {
                                    ctx.reply(data)
                                } else {
                                    // If the task itself failed, don't respond at all
                                    PhantomData
                                }
                            } else {
                                ctx.reply(invalid_arg("not all data is present in connection map"))
                            }
                        } else {
                            ctx.reply(invalid_arg("only 802.11 wireless security is supported"))
                        }
                    }                
                }
            );

            builder.method_with_cr_async(
                "CancelGetSecrets",
                ("connection_path", "setting_name"),
                (),
                move |mut ctx, _cr, (connection_path, setting_name): (Path, String)| {
                    let cr = cr3.clone();
                    let conn = conn.clone();
                    async move {
                        if setting_name == WIFI_SETTING_NAME {
                            // Get more conn info from NetworkManager
                            let proxy = nonblock::Proxy::new("org.freedesktop.NetworkManager", connection_path, Duration::from_secs(2), conn.clone());
                            if let Some((ssid, key_mgmt)) = proxy
                                .method_call::<(PropMapMap,), _, _, _>("org.freedesktop.NetworkManager.Settings.Connection", "GetSettings", ())
                                .await
                                .ok()
                                .as_ref()
                                // extract the ssid and key mgmt out of it
                                .and_then(|(d ,)| parse_connection_data(d))
                            {
                                {
                                    let mut cr_lock = cr.lock().unwrap();
                                    let existing_reqs: &mut ConnectionHandleMap = cr_lock.data_mut(ctx.path()).unwrap();
                                    // find it and abort it
                                    if let Some(handle) = existing_reqs.remove(&(ssid.to_string(), key_mgmt.to_string())) {
                                        handle.abort();
                                    }
                                }
                                ctx.reply(Ok(()))
                            } else {
                                ctx.reply(invalid_arg("invalid or nonexistent connection"))
                            }
                        } else {
                            ctx.reply(invalid_arg("only 802.11 wireless security is supported"))
                        }
                    }
                }
            );

            builder.method_with_cr_async(
                "DeleteSecrets",
                ("connection", "connection_path"),
                (),
                |mut ctx, _cr, (connection, _connection_path): (PropMapMap, Path)| {
                    async move {
                        ctx.reply(delete_passwd_from_connection(&connection).await.map_err(|e| MethodErr::failed(&e)))
                    }
                }
            );

            builder.method_with_cr_async(
                "SaveSecrets",
                ("connection", "connection_path"),
                (),
                |mut ctx, _cr, (mut connection, _connection_path): (PropMapMap, Path)| {
                    async move {
                        ctx.reply(insert_passwd_from_connection(&mut connection).await.map_err(|e| MethodErr::failed(&e)))
                    }
                }
            );
        });

        cr_lock.insert("/org/freedesktop/NetworkManager/SecretAgent", &[iface_token], ConnectionHandleMap::new());
    }

    // Start listening
    conn.start_receive(MatchRule::new_method_call(), Box::new(move |msg, conn| {
        let mut cr_lock = cr.lock().unwrap();
        cr_lock.handle_message(msg, conn).unwrap();
        true
    }));

    // Just run forever
    future::pending::<()>().await;
    unreachable!();
}
