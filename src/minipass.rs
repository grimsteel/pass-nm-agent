use std::{env, process::Stdio};

use tokio::{fs::{try_exists, remove_file, create_dir_all, read_to_string, write},  process::Command, io::AsyncWriteExt};

use crate::error::PassNMError;

fn get_passwd_dir(dir: &str) -> String {
    format!("/home/{}/.password-store/{}", env::var("USER").expect("USER env var exists"), dir)
}

fn get_passwd_file(dir: &str, id: &str) -> String {
    format!("{}/{}.gpg", get_passwd_dir(dir), id)
}

pub async fn passwd_exists(dir: &str, id: &str) -> bool {
    let file_path = get_passwd_file(dir, id);
    try_exists(file_path).await.is_ok_and(|t| t)
}

pub async fn delete_passwd(dir: &str, id: &str) -> Result<(), PassNMError> {
    if !passwd_exists(dir, id).await {
        return Err(PassNMError::NoPassValue);
    }
    
    let file_path = get_passwd_file(dir, id);
    if let Err(err) = remove_file(file_path).await {
        Err(PassNMError::IoError(err))
    } else {
        Ok(())
    }
}

pub async fn read_passwd(dir: &str, id: &str, allow_prompt: bool) -> Result<String, PassNMError> {
    if !passwd_exists(dir, id).await {
        return Err(PassNMError::NoPassValue);
    }
    
    let file_path = get_passwd_file(dir, id);
    let result = Command::new("gpg")
        .arg("--decrypt")
        .arg("--batch")
        // Pinentry Mode is "ask" if we can prompt
        .arg(format!("--pinentry-mode={}", if allow_prompt { "ask" } else { "error" }))
        .arg(file_path)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| PassNMError::IoError(e))?;

    if let Some(0) = result.status.code() {
        let output = String::from_utf8(result.stdout).map_err(|e| PassNMError::Unknown(e.to_string()))?;
        Ok(output.strip_suffix("\n").unwrap_or(&output).to_string())
    } else {
        
        Err(PassNMError::Unknown(format!("gpg process exited with non zero code: {}", String::from_utf8_lossy(&result.stderr).to_string())))
    }
}


pub async fn write_passwd(dir: &str, id: &str, password: &str) -> Result<(), PassNMError> {
    let full_dir = get_passwd_dir(dir);
    let root_dir = get_passwd_dir(".");
    create_dir_all(full_dir).await.map_err(|e| PassNMError::IoError(e))?;

    let gpg_key_id = read_to_string(format!("{}/.gpg-id", root_dir)).await.map_err(|e| PassNMError::IoError(e))?;

    let gpg_key_id = gpg_key_id.strip_suffix("\n").unwrap_or(&gpg_key_id);

    // Spawn GPG to encryp the code
    let mut process = Command::new("gpg")
        .arg("-r")
        .arg(gpg_key_id)
        .arg("--encrypt")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| PassNMError::IoError(e))?;

    let mut stdin = process.stdin.take().ok_or_else(|| PassNMError::Unknown("could not read process stdin".into()))?;

    let password = password.to_string();

    // Write plaintext to gpg
    tokio::spawn(async move {
        stdin.write_all(password.as_bytes()).await.expect("could not write to stdin");
    });

    // Extract encoded out
    let result = process.wait_with_output().await.map_err(|e| PassNMError::IoError(e))?;

    // Write to file
    let file_path = get_passwd_file(dir, id);
    write(file_path, result.stdout).await.map_err(|e| PassNMError::IoError(e))?;

    Ok(())
}    
