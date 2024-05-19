use crate::{error::PassNMError, network_manager::{get_network_by_name, get_network_security_secrets, make_agent_managed, Conn}, service::{delete_stored_secrets, save_secrets}};

// delete a network from pass but not from network manager
pub async fn delete_network(conn: Conn, network: &str) -> Result<(), PassNMError> {
    let network = get_network_by_name(conn, network).await
        .ok_or(PassNMError::NonExistentNetwork)?;

    let security = network.security
        .ok_or(PassNMError::InvalidSecurity)?;

    delete_stored_secrets(&network.id, &security).await?;   
    Ok(())
}

pub async fn insert_network(conn: Conn, network: &str) -> Result<(), PassNMError> {
    // This will not have secrets
    let network = get_network_by_name(conn.clone(), network).await.ok_or(PassNMError::NonExistentNetwork)?;
    let secrets = get_network_security_secrets(conn.clone(), &network).await?;
    
    // Save to pass
    save_secrets(&network.id, &secrets).await?;

    // Remove from NetworkManager
    make_agent_managed(conn, network, &secrets).await?;

    Ok(())
}
