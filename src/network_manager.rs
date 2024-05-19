use std::{collections::HashMap, sync::Arc, time::Duration};

use dbus::{arg::{PropMap, RefArg, Variant}, nonblock::{stdintf::org_freedesktop_dbus::Properties, Proxy, SyncConnection}, Path};
use futures::future::join_all;
use log::debug;

use crate::error::PassNMError;

pub type Conn = Arc<SyncConnection>;
pub type PropMapMap = HashMap<String, PropMap>;

// Struct to wrap a NetworkManager connection
#[derive(Debug)]
pub struct NetworkConnection<'a> {
    pub settings: PropMapMap,
    pub id: String,
    pub security: Option<NetworkSecurity>,
    pub path: Path<'a>
}

impl<'a> TryFrom<(Path<'a>, PropMapMap)> for NetworkConnection<'a> {
    type Error = PassNMError;
    fn try_from((path, settings): (Path<'a>, PropMapMap)) -> Result<Self, Self::Error> {
        let connection = settings.get("connection").ok_or(PassNMError::MissingConnection)?;
        // Get the id (ssid/name)
        let id = connection.get("id")
            .and_then(|id| id.as_str())
            .map(|a| a.to_string())
            .ok_or(PassNMError::MissingConnection)?;

        // Parse the security
        let security = (&settings).try_into().ok();

        Ok(Self { id, path, settings, security })          
    }
}

#[derive(Debug)]
pub enum NetworkSecurity {
    WpaPsk { psk: Option<String>, flags: u32 }
}

impl NetworkSecurity {
    // Get the setting name for GetSecrets
    fn get_secret_setting_name(&self) -> String {
        match self {
            Self::WpaPsk { .. } => "802-11-wireless-security".into()
        }
    }
}

// Convert a single connection item into a secrets-free NetworkSecurity
impl TryFrom<&PropMapMap> for NetworkSecurity {
    type Error = PassNMError;
    fn try_from(value: &PropMapMap) -> Result<Self, Self::Error> {
        (value, value).try_into()
    }
}

// Convert a (secrets, connection) into a NetworkSecurity
impl TryFrom<(&PropMapMap, &PropMapMap)> for NetworkSecurity {
    type Error = PassNMError;
    fn try_from((secrets, connection): (&PropMapMap, &PropMapMap)) -> Result<Self, Self::Error> {
        if let (Some(wifi_secrets), Some(wifi_data)) = (secrets.get("802-11-wireless-security"), connection.get("802-11-wireless-security")) {
            // PSK or EAP
            match wifi_data.get("key-mgmt").and_then(|km| km.as_str()) {
                Some("wpa-psk") => {
                    // We need to get this one from the secrets item
                    let psk = wifi_secrets.get("psk")
                        .and_then(|psk| psk.as_str())
                        // return None if it's empty
                        .and_then(|s| { if s.is_empty() { None } else { Some(s.to_string()) } });
                    
                    let psk_flags = wifi_data.get("psk-flags")
                        // cast to u32
                        .and_then(|flags| flags.as_u64())
                        .map(|flags| flags as u32)
                        .unwrap_or_default();
                    Ok(NetworkSecurity::WpaPsk { psk, flags: psk_flags })
                },
                _ => Err(PassNMError::InvalidSecurity)
            }
        } else {
            Err(PassNMError::InvalidSecurity)
        }
    }
}

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

    debug!("found network on {}: {:?}", result.path, result);

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
pub async fn make_agent_managed<'a>(conn: Conn, network: NetworkConnection<'a>) -> Result<(), PassNMError> {
    // Make the settings mutable so we can set it to agent managed
    let mut settings = network.settings;
    // Figure out what security it uses
    if let Some(security) = network.security {
        match security {
            NetworkSecurity::WpaPsk { psk: _, flags: _ } => {
                settings.get_mut("802-11-wireless-security")
                    .expect("Should have 802-11-wireless-security")
                    .insert(
                        "psk-flags".into(),
                        // 1 = agent managed
                        Variant(Box::new(1 as u32))
                    );
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
    } else {
        Err(PassNMError::InvalidSecurity)
    }
}
