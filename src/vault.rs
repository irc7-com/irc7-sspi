use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use crate::ntlm::calculate_nt_hash;
use serde::{Serialize, Deserialize};

const KEY_FILE: &str = "master.key";
const VAULT_FILE: &str = "credentials.vault";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserLevel {
    Admin,
    Sysop,
    Guide,
}

impl std::fmt::Display for UserLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserLevel::Admin => write!(f, "Admin"),
            UserLevel::Sysop => write!(f, "Sysop"),
            UserLevel::Guide => write!(f, "Guide"),
        }
    }
}

impl std::str::FromStr for UserLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "admin" => Ok(UserLevel::Admin),
            "sysop" => Ok(UserLevel::Sysop),
            "guide" => Ok(UserLevel::Guide),
            _ => Err(format!("Invalid user level: {}. Allowed values: admin, sysop, guide", s)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultAccount {
    #[serde(default)]
    pub username: String,
    pub nt_hash: String,
    pub level: UserLevel,
    pub domain: String,
}

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Crypto(aes_gcm::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    InvalidVault,
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<aes_gcm::Error> for VaultError {
    fn from(e: aes_gcm::Error) -> Self {
        Self::Crypto(e)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<hex::FromHexError> for VaultError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

/// Generates a cryptographically secure 32-byte key if it doesn't exist.
pub fn ensure_master_key() -> Result<(), VaultError> {
    if !Path::new(KEY_FILE).exists() {
        println!("master.key not found. Generating a new 32-byte cryptographically secure key...");
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("Secure random generation failed: {}", e))
        })?;
        let mut file = File::create(KEY_FILE)?;
        file.write_all(&key_bytes)?;
        println!("New key written to master.key.");
    }
    Ok(())
}

/// Helper to read the 32-byte master key from disk.
pub fn load_master_key() -> Result<[u8; 32], VaultError> {
    let mut key_bytes = [0u8; 32];
    let mut file = File::open(KEY_FILE)?;
    file.read_exact(&mut key_bytes)?;
    Ok(key_bytes)
}

/// Loads and decrypts the credentials vault into an ephemeral map.
/// Built with robust backward compatibility for legacy simple vault schemes.
pub fn load_and_decrypt_vault(key: &[u8; 32]) -> Result<HashMap<String, VaultAccount>, VaultError> {
    if !Path::new(VAULT_FILE).exists() {
        return Ok(HashMap::new());
    }

    let file_bytes = fs::read(VAULT_FILE)?;
    if file_bytes.len() < 12 {
        return Err(VaultError::InvalidVault);
    }

    let (nonce_bytes, ciphertext) = file_bytes.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the ciphertext
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)?;
    
    // Attempt to parse new format
    if let Ok(mut map) = serde_json::from_slice::<HashMap<String, VaultAccount>>(&decrypted_bytes) {
        for (k, acc) in map.iter_mut() {
            if acc.username.is_empty() {
                acc.username = k.clone();
            }
        }
        Ok(map)
    } else {
        // Fallback to legacy format
        if let Ok(legacy_map) = serde_json::from_slice::<HashMap<String, String>>(&decrypted_bytes) {
            let mut new_map = HashMap::new();
            for (uname, nt_hash) in legacy_map {
                new_map.insert(uname.to_lowercase(), VaultAccount {
                    username: uname,
                    nt_hash,
                    level: UserLevel::Guide,
                    domain: "ircx.msn.com".to_string(),
                });
            }
            Ok(new_map)
        } else {
            Err(VaultError::InvalidVault)
        }
    }
}

/// Encrypts and writes the credentials map to the vault file.
pub fn encrypt_and_save_vault(key: &[u8; 32], map: &HashMap<String, VaultAccount>) -> Result<(), VaultError> {
    let json_bytes = serde_json::to_vec(map)?;
    
    let cipher = Aes256Gcm::new(key.into());
    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Secure random generation failed: {}", e))
    })?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, json_bytes.as_slice())?;
    
    // Prepend nonce to ciphertext
    let mut vault_data = Vec::with_capacity(12 + ciphertext.len());
    vault_data.extend_from_slice(&nonce_bytes);
    vault_data.extend_from_slice(&ciphertext);
    
    fs::write(VAULT_FILE, vault_data)?;
    Ok(())
}

/// Returns true if the domain string is treated as non-existent.
pub fn is_non_existent_domain(domain: &str) -> bool {
    let d = domain.trim().to_lowercase();
    d.is_empty() || d == "." || d == "workgroup"
}

/// High-level utility to add/update a user in the vault.
pub fn add_user_to_vault(username: &str, password: &str, domain: &str, level: UserLevel) -> Result<(), VaultError> {
    ensure_master_key()?;
    let key = load_master_key()?;
    let mut map = load_and_decrypt_vault(&key)?;
    
    // Calculate raw NT hash (MD4)
    let nt_hash = calculate_nt_hash(password);
    let hex_hash = hex::encode(nt_hash);
    
    let db_domain = if is_non_existent_domain(domain) {
        "".to_string()
    } else {
        domain.trim().to_lowercase()
    };
    
    map.insert(username.to_lowercase(), VaultAccount {
        username: username.trim().to_string(),
        nt_hash: hex_hash,
        domain: db_domain,
        level,
    });
    
    encrypt_and_save_vault(&key, &map)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_roundtrip() {
        use std::path::Path;
        // Back up existing credentials.vault if it exists
        let backup = if Path::new(VAULT_FILE).exists() {
            fs::read(VAULT_FILE).ok()
        } else {
            None
        };

        let key = [42u8; 32];
        let mut map = HashMap::new();
        map.insert("bob".to_string(), VaultAccount {
            username: "bob".to_string(),
            nt_hash: "0123456789abcdef0123456789abcdef".to_string(),
            level: UserLevel::Admin,
            domain: "msn.com".to_string(),
        });
        
        encrypt_and_save_vault(&key, &map).unwrap();
        let loaded = load_and_decrypt_vault(&key).unwrap();
        let account = loaded.get("bob").unwrap();
        assert_eq!(account.nt_hash, "0123456789abcdef0123456789abcdef");
        assert_eq!(account.level, UserLevel::Admin);
        assert_eq!(account.domain, "msn.com");
        
        // Clean up or restore backup
        if let Some(backup_bytes) = backup {
            fs::write(VAULT_FILE, backup_bytes).unwrap();
        } else {
            let _ = fs::remove_file(VAULT_FILE);
        }
    }

    #[test]
    fn test_domain_normalization() {
        assert!(is_non_existent_domain(""));
        assert!(is_non_existent_domain("   "));
        assert!(is_non_existent_domain("."));
        assert!(is_non_existent_domain("workgroup"));
        assert!(is_non_existent_domain("WORKGROUP"));

        assert!(!is_non_existent_domain("msn.com"));
        assert!(!is_non_existent_domain("ircx.msn.com"));
    }

    #[test]
    fn test_case_insensitive_usernames() {
        use std::path::Path;
        // Back up existing credentials.vault if it exists
        let backup = if Path::new(VAULT_FILE).exists() {
            fs::read(VAULT_FILE).ok()
        } else {
            None
        };

        // Add a user with mixed case
        add_user_to_vault("JoshByrnes", "super_secret_password", "msn.com", UserLevel::Admin).unwrap();

        // Load the vault directly to check keys and values
        let key = load_master_key().unwrap();
        let map = load_and_decrypt_vault(&key).unwrap();

        // The map key must be lowercase
        assert!(map.contains_key("joshbyrnes"));
        assert!(!map.contains_key("JoshByrnes"));

        // But the stored struct must preserve the original case
        let account = map.get("joshbyrnes").unwrap();
        assert_eq!(account.username, "JoshByrnes");

        // Clean up or restore backup
        if let Some(backup_bytes) = backup {
            fs::write(VAULT_FILE, backup_bytes).unwrap();
        } else {
            let _ = fs::remove_file(VAULT_FILE);
        }
    }
}
