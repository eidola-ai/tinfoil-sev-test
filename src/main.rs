use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

fn probe() -> String {
    let mut report = String::new();

    // 1. Check /dev/sev-guest existence and permissions
    let sev_path = Path::new("/dev/sev-guest");
    report.push_str(&format!("/dev/sev-guest exists: {}\n", sev_path.exists()));
    if sev_path.exists() {
        match std::fs::metadata(sev_path) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                report.push_str(&format!(
                    "  mode: {:o}, uid: {}, gid: {}\n",
                    m.mode(),
                    m.uid(),
                    m.gid()
                ));
            }
            Err(e) => report.push_str(&format!("  metadata error: {e}\n")),
        }
        // Try opening it
        match std::fs::File::open(sev_path) {
            Ok(_) => report.push_str("  open(read): OK\n"),
            Err(e) => report.push_str(&format!("  open(read): {e}\n")),
        }
        match std::fs::OpenOptions::new().read(true).write(true).open(sev_path) {
            Ok(_) => report.push_str("  open(rw): OK\n"),
            Err(e) => report.push_str(&format!("  open(rw): {e}\n")),
        }
    }

    // 2. Check /dev/sev existence (older interface)
    let sev_path2 = Path::new("/dev/sev");
    report.push_str(&format!("/dev/sev exists: {}\n", sev_path2.exists()));

    // 3. Check /dev/tdx_guest (Intel TDX)
    let tdx_path = Path::new("/dev/tdx_guest");
    report.push_str(&format!("/dev/tdx_guest exists: {}\n", tdx_path.exists()));
    let tdx_path2 = Path::new("/dev/tdx-guest");
    report.push_str(&format!("/dev/tdx-guest exists: {}\n", tdx_path2.exists()));

    // 4. List all /dev entries that might be relevant
    report.push_str("\n/dev entries containing 'sev', 'snp', 'tdx', or 'tee':\n");
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.contains("sev") || name.contains("snp") || name.contains("tdx") || name.contains("tee") {
                report.push_str(&format!("  /dev/{}\n", entry.file_name().to_string_lossy()));
            }
        }
    }

    // 5. Check /sys/kernel/security/tee
    report.push_str("\n/sys/kernel/security/ (tee-related):\n");
    if let Ok(entries) = std::fs::read_dir("/sys/kernel/security") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.contains("tee") || name.contains("sev") || name.contains("tdx") {
                report.push_str(&format!("  {}\n", entry.file_name().to_string_lossy()));
            }
        }
    } else {
        report.push_str("  (not accessible)\n");
    }

    // 6. Check configfs for TSM reports (kernel 6.7+)
    let tsm_path = Path::new("/sys/kernel/config/tsm/report");
    report.push_str(&format!("\n/sys/kernel/config/tsm/report exists: {}\n", tsm_path.exists()));
    if tsm_path.exists() {
        if let Ok(entries) = std::fs::read_dir(tsm_path) {
            for entry in entries.flatten() {
                report.push_str(&format!("  {}\n", entry.file_name().to_string_lossy()));
            }
        }
    }
    // Also check if configfs is mounted at all
    let configfs = Path::new("/sys/kernel/config");
    report.push_str(&format!("/sys/kernel/config exists: {}\n", configfs.exists()));

    // 7. Check /tinfoil ramdisk (what the shim exposes)
    report.push_str("\n/tinfoil/ contents:\n");
    if let Ok(entries) = std::fs::read_dir("/tinfoil") {
        for entry in entries.flatten() {
            report.push_str(&format!("  {}\n", entry.file_name().to_string_lossy()));
        }
    } else {
        report.push_str("  (not accessible or doesn't exist)\n");
    }

    // 8. Check /mnt/ramdisk (where boot writes attestation)
    report.push_str("\n/mnt/ramdisk/ contents:\n");
    fn list_recursive(path: &Path, prefix: &str, report: &mut String) {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if p.is_dir() {
                    report.push_str(&format!("{}{}/\n", prefix, name));
                    list_recursive(&p, &format!("{}  ", prefix), report);
                } else {
                    let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    report.push_str(&format!("{}{} ({} bytes)\n", prefix, name, size));
                }
            }
        }
    }
    if Path::new("/mnt/ramdisk").exists() {
        list_recursive(Path::new("/mnt/ramdisk"), "  ", &mut report);
    } else {
        report.push_str("  (not accessible or doesn't exist)\n");
    }

    // 9. Current user/groups
    report.push_str(&format!("\nuid: {}, gid: {}\n",
        unsafe { libc::getuid() }, unsafe { libc::getgid() }));

    // 10. Try reading the attestation report if accessible
    let att_path = "/mnt/ramdisk/attestation.json";
    if Path::new(att_path).exists() {
        match std::fs::read_to_string(att_path) {
            Ok(contents) => {
                let preview = if contents.len() > 500 { &contents[..500] } else { &contents };
                report.push_str(&format!("\nattestation.json preview:\n{preview}\n...\n"));
            }
            Err(e) => report.push_str(&format!("\nattestation.json read error: {e}\n")),
        }
    }

    report
}

fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).unwrap();
    eprintln!("sev-probe listening on :{port}");

    for stream in listener.incoming().flatten() {
        let mut buf = [0u8; 4096];
        let _ = stream.peek(&mut buf); // consume the request
        let mut stream = stream;
        let _ = Read::read(&mut stream, &mut buf);

        let body = probe();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    }
}

// Minimal libc bindings for getuid/getgid
mod libc {
    extern "C" {
        pub fn getuid() -> u32;
        pub fn getgid() -> u32;
    }
}
