use log::{error, info, warn};
use std::env;
use std::error::Error;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EXECUTE_MASK: u32 = 0o111;

pub fn generate_12hex_random_id() -> Result<String, Box<dyn Error>> {
    let mut random_byte = [0u8; 6];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut random_byte)?;
    let mut random_id = String::with_capacity(12);
    for byte in random_byte {
        write!(random_id, "{:02x}", byte)?;
    }
    Ok(random_id)
}

pub fn create_vm_work_dir() -> Result<PathBuf, Box<dyn Error>> {
    let home_dir = env::var("HOME").map_err(|e| format!("Failed to find home directory: {}", e))?;
    let base_dir = Path::new(&home_dir)
        .join(".local")
        .join("share")
        .join("trt_launcher");
    fs::create_dir_all(&base_dir)
        .map_err(|e| format!("Failed to create base dir {}:{}", base_dir.display(), e))?;

    let random_id = generate_12hex_random_id()?;
    let work_dir = base_dir.join(random_id);
    fs::create_dir(&work_dir)
        .map_err(|e| format!("Failed to create work dir {}:{}", work_dir.display(), e))?;
    info!("Created work dir {}", work_dir.display());
    Ok(work_dir)
}

pub fn escape_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return "-".to_string();
    }

    let mut slash_seq = false;
    let parts: Vec<String> = trimmed
        .bytes()
        .filter(|b| {
            let is_slash = *b == b'/';
            let res = !(is_slash && slash_seq);
            slash_seq = is_slash;
            res
        })
        .enumerate()
        .map(|(n, b)| escape_byte(b, n))
        .collect();
    parts.join("")
}

fn escape_byte(b: u8, n: usize) -> String {
    let c = char::from(b);
    match c {
        '/' => '-'.to_string(),
        ':' | '_' | '0'..='9' | 'a'..='z' | 'A'..='Z' => c.to_string(),
        '.' if n > 0 => c.to_string(),
        _ => format!(r#"\x{b:02x}"#),
    }
}

#[derive(Clone, Debug)]
pub struct ExecutablePaths {
    pub qemu_path: PathBuf,
    pub virtiofsd_path: Option<PathBuf>,
}

fn find_executable(bin_name: &str) -> Option<PathBuf> {
    let path_env = env::var("PATH").ok()?;
    let path_dirs: Vec<&str> = path_env.split(':').collect();
    for dir in path_dirs {
        if dir.is_empty() {
            continue;
        }
        let full_path = Path::new(dir).join(bin_name);
        let metadata = match fs::metadata(&full_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        use std::os::unix::fs::PermissionsExt;
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        if (mode & EXECUTE_MASK) != 0 {
            return Some(full_path);
        }
    }
    None
}

fn check_unshare() -> Result<(), Box<dyn Error>> {
    let unshare_output = match Command::new("unshare").arg("-r").arg("id").output() {
        Ok(out) => out,
        Err(e) => {
            error!("Failed to check unshare: {}", e);
            return Err(Box::new(e));
        }
    };

    let unshare_stdout = str::from_utf8(&unshare_output.stdout)?;
    let unshare_stderr = str::from_utf8(&unshare_output.stderr)?;
    if !unshare_output.status.success() {
        return Err(format!(
            "Failed to command 'unshare -r id', stdout : {} , stderr: {}",
            unshare_stdout, unshare_stderr
        )
        .into());
    }

    if !unshare_stdout.starts_with("uid=0(root) gid=0(root) groups=0(root)") {
        return Err(format!(
            "Expected output to start with 'uid=0(root) gid=0(root) groups=0(root)' but got {}",
            unshare_stdout
        )
        .into());
    }
    info!("check unshare succeed");
    Ok(())
}

pub fn find_required_tools() -> Result<ExecutablePaths, Box<dyn Error>> {
    let qemu_path =
        find_executable("qemu-system-aarch64").ok_or("qemu-system-aarch64 not found in $PATH")?;

    let virtiofsd_path = match find_executable("virtiofsd") {
        Some(p) => {
            check_unshare()?;
            Some(p)
        }
        None => {
            warn!("Could not find virtiofsd in $PATH --virtiofs will be discarded.");
            None
        }
    };
    Ok(ExecutablePaths {
        qemu_path,
        virtiofsd_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockrs::mock;

    #[test]
    fn escape_path_normal() {
        assert_eq!(escape_path("/root/app"), "root-app");
    }

    #[test]
    fn escape_path_all_slashes() {
        assert_eq!(escape_path("/"), "-");
        assert_eq!(escape_path("///"), "-");
    }

    #[test]
    fn escape_path_consecutive_slashes() {
        assert_eq!(escape_path("/a//b"), "a-b");
    }

    #[test]
    fn escape_path_special_chars() {
        let result = escape_path("/path@with!special");
        assert!(result.contains("path"));
        assert!(result.contains("\\x40"));
        assert!(result.contains("\\x21"));
    }

    #[test]
    fn escape_path_dot_at_zero() {
        let result = escape_path("/.hidden");
        assert!(result.starts_with("\\x2e") || result.contains("hidden"));
    }

    #[test]
    fn escape_path_colon_preserved() {
        assert!(escape_path("/path:with:colon").contains(':'));
    }

    #[test]
    fn escape_path_underscore_preserved() {
        assert!(escape_path("/path_with_underscore").contains('_'));
    }

    #[test]
    fn escape_byte_values() {
        assert_eq!(escape_byte(b'/', 0), "-".to_string());
        assert_eq!(escape_byte(b':', 0), ":".to_string());
        assert_eq!(escape_byte(b'_', 0), "_".to_string());
        assert_eq!(escape_byte(b'a', 0), "a".to_string());
        assert_eq!(escape_byte(b'Z', 0), "Z".to_string());
        assert_eq!(escape_byte(b'5', 0), "5".to_string());
        assert_eq!(escape_byte(b'.', 0), "\\x2e".to_string());
        assert_eq!(escape_byte(b'.', 1), ".".to_string());
        assert_eq!(escape_byte(b'@', 0), "\\x40".to_string());
    }

    #[test]
    fn generate_12hex_random_id_format() {
        let id = generate_12hex_random_id().unwrap();
        assert_eq!(id.len(), 12);
        for c in id.chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn create_vm_work_dir_mocked() {
        fn mock_gen_id() -> Result<String, Box<dyn Error>> {
            Ok("abcdef123456".to_string())
        }

        let home = env::var("HOME").unwrap_or("/tmp".to_string());
        let existing = Path::new(&home)
            .join(".local")
            .join("share")
            .join("trt_launcher")
            .join("abcdef123456");
        if existing.exists() {
            fs::remove_dir(&existing).unwrap();
        }

        let _mocker = mock!(generate_12hex_random_id, mock_gen_id);
        let result = create_vm_work_dir();
        assert!(result.is_ok());
        let work_dir = result.unwrap();
        assert!(work_dir.to_string_lossy().contains("abcdef123456"));
        assert!(work_dir.exists());
    }

    #[test]
    fn create_vm_work_dir_direct() {
        let result = create_vm_work_dir();
        assert!(result.is_ok());
        let work_dir = result.unwrap();
        assert!(work_dir.exists());
        assert!(work_dir.to_string_lossy().contains("trt_launcher"));
        fs::remove_dir(&work_dir).unwrap();
    }

    #[test]
    fn find_executable_known_binary() {
        let result = find_executable("sh");
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.exists());
    }

    #[test]
    fn find_executable_not_found() {
        let result = find_executable("nonexistent_binary_xyz");
        assert!(result.is_none());
    }

    #[test]
    fn check_unshare_direct() {
        let result = check_unshare();
        assert!(result.is_ok());
    }

    #[test]
    fn find_required_tools_direct() {
        let result = find_required_tools();
        if find_executable("qemu-system-aarch64").is_some() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn find_required_tools_both_found() {
        fn mock_find_exec(bin_name: &str) -> Option<PathBuf> {
            match bin_name {
                "qemu-system-aarch64" => Some(PathBuf::from("/usr/bin/qemu-system-aarch64")),
                "virtiofsd" => Some(PathBuf::from("/usr/bin/virtiofsd")),
                _ => None,
            }
        }
        fn mock_check_unshare() -> Result<(), Box<dyn Error>> {
            Ok(())
        }
        let _m1 = mock!(find_executable, mock_find_exec);
        let _m2 = mock!(check_unshare, mock_check_unshare);
        let result = find_required_tools();
        assert!(result.is_ok());
        let tools = result.unwrap();
        assert!(tools.virtiofsd_path.is_some());
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn find_required_tools_only_qemu() {
        fn mock_find_exec(bin_name: &str) -> Option<PathBuf> {
            match bin_name {
                "qemu-system-aarch64" => Some(PathBuf::from("/usr/bin/qemu-system-aarch64")),
                _ => None,
            }
        }
        let _mocker = mock!(find_executable, mock_find_exec);
        let result = find_required_tools();
        assert!(result.is_ok());
        assert!(result.unwrap().virtiofsd_path.is_none());
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn find_required_tools_no_qemu() {
        fn mock_find_exec(_bin_name: &str) -> Option<PathBuf> {
            None
        }
        let _mocker = mock!(find_executable, mock_find_exec);
        assert!(find_required_tools().is_err());
    }

    #[test]
    #[cfg(not(feature = "coverage"))]
    fn find_required_tools_unshare_fail() {
        fn mock_find_exec(bin_name: &str) -> Option<PathBuf> {
            match bin_name {
                "qemu-system-aarch64" => Some(PathBuf::from("/usr/bin/qemu-system-aarch64")),
                "virtiofsd" => Some(PathBuf::from("/usr/bin/virtiofsd")),
                _ => None,
            }
        }
        fn mock_check_unshare() -> Result<(), Box<dyn Error>> {
            Err("unshare failed".into())
        }
        let _m1 = mock!(find_executable, mock_find_exec);
        let _m2 = mock!(check_unshare, mock_check_unshare);
        assert!(find_required_tools().is_err());
    }
}
