// SPDX-License-Identifier: GPL-3.0-only

#![allow(clippy::uninlined_format_args)]

use buildchain::{download, DownloadArguments};
use clap::{App, Arg};
use std::process;

fn buildchain() -> Result<(), String> {
    let matches = App::new("buildchain")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand(
            App::new("download")
                .about("Download from a buildchain project")
                .arg(
                    Arg::new("project")
                        .long("project")
                        .takes_value(true)
                        .help("Tail signature project name"),
                )
                .arg(
                    Arg::new("branch")
                        .long("branch")
                        .takes_value(true)
                        .help("Tail signature branch name"),
                )
                .arg(
                    Arg::new("cert")
                        .long("cert")
                        .takes_value(true)
                        .help("Remote URL certificate"),
                )
                .arg(
                    Arg::new("cache")
                        .long("cache")
                        .takes_value(true)
                        .help("Local cache"),
                )
                .arg(
                    Arg::new("key")
                        .takes_value(true)
                        .required(true)
                        .help("Remote public key"),
                )
                .arg(
                    Arg::new("url")
                        .takes_value(true)
                        .required(true)
                        .help("Remote URL"),
                )
                .arg(Arg::new("file").takes_value(true).help("Requested file")),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("download") {
        download(DownloadArguments {
            project: matches.value_of("project").unwrap_or("default"),
            branch: matches.value_of("branch").unwrap_or("master"),
            cert_opt: matches.value_of("cert"),
            cache_opt: matches.value_of("cache"),
            key: matches.value_of("key").unwrap(),
            url: matches.value_of("url").unwrap(),
            file_opt: matches.value_of("file"),
        })
    } else {
        Err("no subcommand provided".to_string())
    }
}

fn main() {
    match buildchain() {
        Ok(()) => (),
        Err(err) => {
            eprintln!("buildchain: {}", err);
            process::exit(1);
        }
    }
}
