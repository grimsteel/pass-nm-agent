use std::{collections::HashMap, sync::Arc};

use dbus::{arg::{PropMap, RefArg}, nonblock::SyncConnection, Path};
use itertools::Itertools;

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
pub struct PwWithFlags {
    pub pw: Option<String>,
    pub flags: u32
}

#[derive(Debug)]
pub enum NetworkSecurity {
    WpaPsk(PwWithFlags),
    WpaEap { client_cert_pw: PwWithFlags, private_key_pw: PwWithFlags, password: PwWithFlags },
    // peer_psks is a map of pubkey to psk
    Wireguard { private_key: PwWithFlags, peer_psks: HashMap<String, PwWithFlags> }
}

impl NetworkSecurity {
    // Get the setting name for GetSecrets
    pub fn get_secret_setting_name(&self) -> String {
        match self {
            Self::WpaPsk(..) => "802-11-wireless-security".into(),
            Self::WpaEap { .. } => "802-1x".into(),
            Self::Wireguard { .. } => "wireguard".into()
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
                    Ok(Self::WpaPsk(parse_pw_with_flags(wifi_data, wifi_secrets, "psk")))
                },
                Some("wpa-eap") => {
                    // Get the 802.1x information
                    if let (Some(wifi_8021x_secrets), Some(wifi_8021x)) = (secrets.get("802-1x"), connection.get("802-1x")) {
                        Ok(Self::WpaEap {
                            password: parse_pw_with_flags(wifi_8021x, wifi_8021x_secrets, "password"),
                            client_cert_pw: parse_pw_with_flags(wifi_8021x, wifi_8021x_secrets, "client-cert-password"),
                            private_key_pw: parse_pw_with_flags(wifi_8021x, wifi_8021x_secrets, "private-key-password")
                        })
                    } else {
                        Err(PassNMError::InvalidSecurity)
                    }
                },
                _ => Err(PassNMError::InvalidSecurity)
            }
        } else if let (Some(wireguard), Some(wireguard_secrets)) = (connection.get("wireguard"), secrets.get("wireguard")) {
            // We can store the WG private key and the pre-shared keys of the peers

            let peers = wireguard.get("peers")
                .and_then(|p| p.0.as_iter());
            
            let peers_secrets = wireguard_secrets.get("peers")
                .and_then(|p| p.0.as_iter());
            
            // Iterate and map all of the peers into a HashMap of ID (pubkey) to PSK
            let peer_psks = if let (Some(peers), Some(peers_secrets)) = (peers, peers_secrets) {
                peers.zip(peers_secrets).fold(HashMap::new(), |mut map, (peer, peer_secrets)| {

                    // We can't cast to PropMap without a clone because casting requires they live for static
                    let mut psk: Option<String> = None;
                    let mut psk_flags: Option<u32> = None;
                    let mut pubkey: Option<String> = None;
                    // Iterate over the peer PropMap
                    if let Some(peer) = peer.as_iter() {
                        for (key, value) in peer.tuples() {
                            
                            match key.as_str() {
                                Some("public-key") => if let Some(public_key) = value.as_str() { pubkey = Some(public_key.into()) },
                                // Found psk flags - cast to u32 
                                Some("preshared-key-flags") => if let Some(preshared_key_flags) = value.as_u64() { psk_flags = Some(preshared_key_flags as u32) }
                                _ => {}
                            }

                            if psk_flags.is_some() && pubkey.is_some() {
                                break;
                            } 
                        }
                    }

                    if let Some(pubkey) = pubkey {                    
                        // Iterate over peer_secrets
                        if let Some(peer_secrets) = peer_secrets.as_iter() {
                            for (key, value) in peer_secrets.tuples() {
                                if let (Some("preshared-key"), Some(preshared_key)) = (key.as_str(), value.as_str()) {
                                    psk = Some(preshared_key.into());
                                    break;
                                }
                            }
                        }
                        map.insert(pubkey, PwWithFlags { pw: psk, flags: psk_flags.unwrap_or_default() });
                    }

                    map
                })
            } else {
                // This wg connection has no friends :(
                HashMap::new()
            };
            
            Ok(Self::Wireguard { private_key: parse_pw_with_flags(wireguard, wireguard_secrets, "private-key"), peer_psks })
        } else {
            Err(PassNMError::InvalidSecurity)
        }
    }
}

fn parse_pw_with_flags(settings: &PropMap, secrets: &PropMap, setting_name: &str) -> PwWithFlags {
    let pw = secrets.get(setting_name)
        .and_then(|pw| pw.as_str())
        .and_then(|s| { if s.is_empty() { None } else { Some(s.to_string()) } } );

    // Get the flags
    let pw_flags = settings.get(&format!("{}-flags", setting_name))
        .and_then(|flags| flags.as_u64())
        .map(|flags| flags as u32)
        .unwrap_or_default();

    PwWithFlags { pw, flags: pw_flags }
}
