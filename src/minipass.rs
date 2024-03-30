use std::{env, process::Stdio};

use tokio::{fs::{try_exists, remove_file, create_dir_all, read_to_string, write},  process::Command, io::AsyncWriteExt};

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

pub async fn delete_passwd(dir: &str, id: &str) -> Result<(), String> {
    if !passwd_exists(dir, id).await {
        return Err("secret does not exist".to_string());
    }
    
    let file_path = get_passwd_file(dir, id);
    if remove_file(file_path).await.is_ok() {
        Ok(())
    } else {
        Err("could not delete secret".to_string())
    }
}

pub async fn read_passwd(dir: &str, id: &str, allow_prompt: bool) -> Result<String, String> {
    if !passwd_exists(dir, id).await {
        return Err("no secrets available".to_string());
    }
    
    let file_path = get_passwd_file(dir, id);
    let result = Command::new("gpg")
        .arg("--decrypt")
        .arg("--batch")
        .arg(format!("--pinentry-mode={}", if allow_prompt { "ask" } else { "error" }))
        .arg(file_path)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|_e| "Could not spawn gpg")?;

    if let Some(0) = result.status.code() {
        let output = String::from_utf8(result.stdout).map_err(|_e| "Could not read gpg output")?;
        Ok(output.strip_suffix("\n").unwrap_or(&output).to_string())
    } else {
        Err(format!("gpg process exited with non zero code: {}", String::from_utf8_lossy(&result.stderr).to_string()))
    }
}


pub async fn write_passwd(dir: &str, id: &str, password: &str) -> Result<(), String> {
    let full_dir = get_passwd_dir(dir);
    let root_dir = get_passwd_dir(".");
    create_dir_all(full_dir).await.map_err(|_| "could not create passwd dir")?;

    let gpg_key_id = read_to_string(format!("{}/.gpg-id", root_dir)).await.map_err(|_| "could not read gpg key id")?;

    let gpg_key_id = gpg_key_id.strip_suffix("\n").unwrap_or(&gpg_key_id);

    let mut process = Command::new("gpg")
        .arg("-r")
        .arg(gpg_key_id)
        .arg("--encrypt")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "could not spawn gpg")?;

    let mut stdin = process.stdin.take().ok_or_else(|| "could not get gpg stdin")?;

    let password = password.to_string();

    tokio::spawn(async move {
        stdin.write_all(password.as_bytes()).await.expect("could not write to stdin");
    });

    let result = process.wait_with_output().await.map_err(|_| "could not wait for gpg to complete")?;
    
    let file_path = get_passwd_file(dir, id);
    write(file_path, result.stdout).await.map_err(|_| "could not write file")?;

    Ok(())
}    
