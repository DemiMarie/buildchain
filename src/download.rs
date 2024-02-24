// SPDX-License-Identifier: GPL-3.0-only

use std::fs::File;
use std::io::{stdout, Read, Write};
use std::process::{Command, Stdio};

use crate::block::PackedBlock;
use crate::store::b32dec;
use crate::{err_str, Block, Manifest, Sha384};

pub struct DownloadArguments<'a> {
    pub project: &'a str,
    pub branch: &'a str,
    pub cert_opt: Option<&'a str>,
    pub cache_opt: Option<&'a str>,
    pub key: &'a str,
    pub url: &'a str,
    pub file_opt: Option<&'a str>,
}

pub struct Downloader {
    key: Vec<u8>,
    url: String,
    project: String,
    branch: String,
    cert_opt: Option<Vec<u8>>,
}

impl Downloader {
    pub fn new(
        key: &str,
        url: &str,
        project: &str,
        branch: &str,
        cert_opt: Option<&[u8]>,
    ) -> Result<Downloader, String> {
        let key = b32dec(key).ok_or_else(|| "key not in base32 format".to_string())?;

        let url = url.to_owned();

        Ok(Downloader {
            key,
            url,
            project: project.to_string(),
            branch: branch.to_string(),
            cert_opt: cert_opt.map(|x| x.to_owned()),
        })
    }

    fn download(&self, path: &str) -> Result<Vec<u8>, String> {
        let url = self.url.to_owned() + "/" + path;
        let updatevm = Command::new("/usr/bin/qubes-prefs")
            .arg("updatevm")
            .output()
            .map_err(|e| e.to_string())?
            .stdout;
        let updatevm = String::from_utf8(updatevm).map_err(|e| e.to_string())?;
        let updatevm = updatevm.trim();
        if let Some(cert) = self.cert_opt.as_ref() {
            let mut cmd = Command::new("/usr/bin/qvm-run");
            cmd.args(&[
                "--pass-io",
                "-qa",
                "--autostart",
                "--user=root",
                "--",
                &updatevm,
                // FIXME: ugly hack
                // FIXME: racy!
                "umask 0022 && cat > /run/update-cert.pem",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null());
            let child = cmd.spawn().map_err(|e| e.to_string())?;
            child
                .stdin
                .as_ref()
                .expect("stdlib bug")
                .write_all(&*cert)
                .map_err(|e| e.to_string())?;
            let output = child.wait_with_output().map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err(format!(
                    "Failed to write certificate file: {}",
                    output.status
                ));
            }
        }
        let mut cmd = Command::new("/usr/bin/qvm-run");
        cmd.args(&[
            "--pass-io",
            "-qa",
            "--autostart",
            "--no-shell",
            "--",
            &updatevm,
            "curl",
        ])
        .stdout(Stdio::piped());
        if self.cert_opt.is_some() {
            cmd.args(&["--cacert", "/run/update-cert.pem"]);
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let child = cmd.args(&["--", &url]).spawn().map_err(|e| e.to_string())?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "Child process exited with status {}",
                output.status
            ));
        }
        Ok(output.stdout)
    }

    pub fn object(&self, digest: &str) -> Result<Vec<u8>, String> {
        let path = format!("object/{}", digest);
        let data = self.download(&path)?;

        let sha = Sha384::new(data.as_slice()).map_err(err_str)?;
        if sha.to_base32() != digest {
            return Err("sha384 mismatch".to_string());
        }

        Ok(data)
    }

    pub fn tail(&self) -> Result<Block, String> {
        let path = format!("tail/{}/{}", self.project, self.branch);
        let data = self.download(&path)?;

        let b: &PackedBlock =
            plain::from_bytes(&data).map_err(|_| "response too small".to_string())?;
        b.verify(&self.key)
    }
}

pub fn download(args: DownloadArguments) -> Result<(), String> {
    let mut cert = Vec::new();
    let cert_opt = if let Some(cert_path) = args.cert_opt {
        {
            let mut file = File::open(cert_path).map_err(err_str)?;
            file.read_to_end(&mut cert).map_err(err_str)?;
        }
        Some(cert.as_slice())
    } else {
        None
    };

    let dl = Downloader::new(args.key, args.url, args.project, args.branch, cert_opt)?;

    let tail = dl.tail()?;

    let manifest_json = dl.object(&tail.digest)?;
    let manifest = serde_json::from_slice::<Manifest>(&manifest_json).map_err(err_str)?;

    if let Some(file) = args.file_opt {
        if let Some(digest) = manifest.files.get(file) {
            let data = dl.object(digest)?;
            stdout().write(&data).map_err(err_str)?;
        } else {
            return Err(format!("{} not found", file));
        }
    } else {
        for (file, _digest) in manifest.files.iter() {
            println!("{}", file);
        }
    }

    Ok(())
}
