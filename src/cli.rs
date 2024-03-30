use std::{time::Duration, sync::Arc, error::Error};

use dbus::{nonblock::{Proxy, stdintf::org_freedesktop_dbus::Properties, SyncConnection}, Path, arg::{RefArg, Variant}};

use crate::{service::{PropMapMap, parse_connection_data, delete_passwd_from_connection, WIFI_SETTING_NAME, PASS_DIR}, minipass::write_passwd};

async fn get_network(conn: Arc<SyncConnection>, network: &str) -> Result<(Path, PropMapMap), Box<dyn Error>> {
    let nm_proxy = Proxy::new("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings", Duration::from_secs(2), conn.clone());

    let connections = nm_proxy.get::<Vec<Path>>("org.freedesktop.NetworkManager.Settings", "Connections").await?;

    let network_data =
        // read all connections
        futures::future::join_all(
            connections
                .into_iter()
                .map(|path| {
                    let p = Proxy::new("org.freedesktop.NetworkManager", path.clone(), Duration::from_secs(2), conn.clone());
                    tokio::spawn(async move {
                        p.method_call::<(PropMapMap, ), _, _, _>("org.freedesktop.NetworkManager.Settings.Connection", "GetSettings", ()).await.map(move |t| (path, t.0))
                    })
                })
        )
        .await
        .into_iter()
        .flatten()
        .flatten()
        // find this specific one
        .find(|(_, t)| {
            if let Some((ssid, _)) = parse_connection_data(t) {
                if ssid == network {
                    return true;
                }
            }
            return false;
        });
        

    Ok(network_data.ok_or_else(|| "network not found")?)
}

// delete a network from pass but not from network manager
pub async fn delete_network(conn: Arc<SyncConnection>, network: &str) -> Result<(), Box<dyn Error>> {
    let (_, network) = get_network(conn, network).await?;

    delete_passwd_from_connection(&network).await?;

    Ok(())
}

pub async fn insert_network(conn: Arc<SyncConnection>, network: &str) -> Result<(), Box<dyn Error>> {
    let (path, mut network) = get_network(conn.clone(), network).await?;
    
    //insert_passwd_from_connection(&mut network).await?;
    let (ssid, key_mgmt) = parse_connection_data(&network).unwrap();

    let p = Proxy::new("org.freedesktop.NetworkManager", path, Duration::from_secs(2), conn);
    let secrets = p.method_call::<(PropMapMap, ), _, _, _>("org.freedesktop.NetworkManager.Settings.Connection", "GetSecrets", (WIFI_SETTING_NAME, )).await?;
    let secrets = secrets.0.get(WIFI_SETTING_NAME).ok_or_else(|| "no secrets exist on this network")?;

    match key_mgmt {
        "wpa-psk" => {
            let psk = secrets.get("psk").and_then(|i| i.as_str()).ok_or_else(|| "psk field does not exist")?;
            write_passwd(PASS_DIR, &format!("{}.wpa-psk", ssid), psk).await?;
            // set it to agent managed
            network.get_mut(WIFI_SETTING_NAME).unwrap().insert("psk-flags".into(), Variant(Box::new(1 as u32)));
            p.method_call("org.freedesktop.NetworkManager.Settings.Connection", "Update", (network, )).await?;
            // remove secret
            //p.method_call("org.freedesktop.NetworkManager.Settings.Connection", "ClearSecrets", ()).await?;
            Ok(())
        },
        _ => Err("unsupported wifi key mgmt".into())
    }
}
