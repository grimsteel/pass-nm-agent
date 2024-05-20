use std::{collections::HashMap, sync::Arc, time::Duration};

use dbus::{arg::{PropMap, RefArg, Variant}, nonblock::{stdintf::org_freedesktop_dbus::Properties, Proxy, SyncConnection}, Path};
use futures::future::join_all;
use log::debug;

use crate::error::PassNMError;
use crate::model::{NetworkSecurity, NetworkConnection, Conn, PropMapMap};

fn make_proxy<'a, P: Into<Path<'a>>>(conn: Conn, path: P) -> Proxy<'a, Conn> {
    Proxy::new("org.freedesktop.NetworkManager", path, Duration::from_secs(2), conn)
}

pub async fn get_network<'a>(conn: Conn, path: Path<'a>) -> Result<NetworkConnection<'a>, PassNMError> {
    debug!("get network on {}", path);

    // Call the GetSettings method to get the connection details
    let settings = make_proxy(conn, path.clone()) 
       .method_call::<(PropMapMap, ), _, _, _>(
            "org.freedesktop.NetworkManager.Settings.Connection",
            "GetSettings",
            ()
        ).await.map_err(|e| PassNMError::DbusError(e))?;

    let result: NetworkConnection = (path, settings.0).try_into()?;

    //debug!("found network on {}: {:?}", result.path, result);

    Ok(result)
}

// Returns a hash map of SSID to path + 
pub async fn list_connections<'a>(conn: Arc<SyncConnection>) -> HashMap<String, NetworkConnection<'a>> {
    let connections = make_proxy(conn.clone(),  "/org/freedesktop/NetworkManager/Settings")
        .get::<Vec<Path>>("org.freedesktop.NetworkManager.Settings", "Connections").await.unwrap_or_default();

    let connection_data = join_all(
        connections.into_iter()
            .map(|path| {
                let c = conn.clone();
                // Spawn a task to get the actual connection details
                tokio::spawn(async move {
                    get_network(c, path).await
                })
            })
    )
        .await
        .into_iter()
        .flatten()
        .flatten()
        .fold(HashMap::new(), |mut map, network| {
            map.insert(network.id.clone(), network);
            map
        });

    debug!("found {} networks: {:?}", connection_data.len(), connection_data);

    connection_data
}

pub async fn get_network_by_name(conn: Conn, name: &str) -> Option<NetworkConnection> {
    let mut networks = list_connections(conn).await;
    networks.remove(name)
}

// Returns a NetworkSecurity object with secret information
pub async fn get_network_security_secrets<'a>(conn: Conn, network: &NetworkConnection<'a>) -> Result<NetworkSecurity, PassNMError> {
    debug!("get secrets for {}", network.path);
    // The network needs _some_ security information
    if let Some(security) = &network.security {
        // Call GetSecrets
        let (secrets, ) = make_proxy(conn, network.path.clone())
            .method_call::<(PropMapMap, ), _, _, _>(
                "org.freedesktop.NetworkManager.Settings.Connection",
                "GetSecrets",
                (security.get_secret_setting_name(), )
            ).await.map_err(|e| PassNMError::DbusError(e))?;

        // Parse into a NetworkSecurity
        let results: NetworkSecurity = (&secrets, &network.settings).try_into()?;

        debug!("found secrets for {}: {:?}", network.path, results);

        Ok(results)
    } else {
        Err(PassNMError::InvalidSecurity)
    }
}

// Set all secrets to agent-managed in a NetworkManager Connection Settings
pub async fn make_agent_managed<'a>(conn: Conn, network: NetworkConnection<'a>, full_secrets: &NetworkSecurity) -> Result<(), PassNMError> {
    // Make the settings mutable so we can set it to agent managed
    let mut settings = network.settings;

    // 1 = agent managed
    let agent_managed: Box<dyn RefArg> = Box::new(1 as u32);

    let item_settings = settings.get_mut(&full_secrets.get_secret_setting_name()).expect("should have this item");

    // Figure out what security it uses
    match full_secrets {
        NetworkSecurity::WpaPsk(psk) => {
            if psk.pw.is_some() {
                item_settings
                    .insert(
                        "psk-flags".into(),
                        Variant(agent_managed)
                    );
            }
        },
        NetworkSecurity::WpaEap { client_cert_pw, private_key_pw, password } => {
            // If there was a client cert pw
            if client_cert_pw.pw.is_some() {
                item_settings.insert("client-cert-password-flags".into(), Variant(agent_managed.box_clone()));
            }

            if private_key_pw.pw.is_some() {
                item_settings.insert("private-key-password-flags".into(), Variant(agent_managed.box_clone()));
            }

            if password.pw.is_some() {
                item_settings.insert("password-flags".into(), Variant(agent_managed));
            }
        },
        NetworkSecurity::Wireguard { private_key, peer_psks } => {
            if private_key.pw.is_some() {
                item_settings.insert("private-key-flags".into(), Variant(agent_managed.box_clone()));
            }

            // I have no clue what's going on here with the array of propmaps. This is the onyl way that worked
            if let Some(peers) = item_settings.get("peers") {
                let length = peers.0.as_iter()
                    .map(|a| a.count())
                    .unwrap_or_default();

                let new_peers: Vec<PropMap> = (0..length)
                    .filter_map(|i| {
                        if let Some(peer) = peers.0
                            .as_static_inner(i)
                            .and_then(|p| dbus::arg::cast::<PropMap>(p)) {
                                // Clone the map (why is this so hard???)
                                let mut map = PropMap::new();
                                for (k, v) in peer {
                                    map.insert(k.into(), Variant(v.0.box_clone()));
                                }
                                if let Some(pubkey) = map.get("public-key").and_then(|a| a.as_str()) {
                                    // If this peer actually has a psk
                                    if peer_psks.get(pubkey).map(|psk| psk.pw.is_some()).unwrap_or(false) {
                                        map.insert("preshared-key-flags".into(), Variant(agent_managed.box_clone()));
                                    }
                                }
                                Some(map)
                            } else { None }
                    })
                    .collect();
                
                item_settings.insert("peers".into(), Variant(Box::new(new_peers)));
            }
        }
    }

    // Update in NetworkManager
    make_proxy(conn, network.path)
        .method_call(
            "org.freedesktop.NetworkManager.Settings.Connection",
            "Update",
            (settings, )
        ).await.map_err(|e| PassNMError::DbusError(e))?;
    
    Ok(())
}
