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

#[allow(clippy::incompatible_msrv)]
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
