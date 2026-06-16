use argh::FromArgs;
use std::fs::{create_dir_all, remove_dir_all};
use std::path::{Path, PathBuf};
use std::process;
use walkdir::WalkDir;
#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "compile")]
/// Compile
pub struct CompileCmd {
    #[argh(option, short = 'i')]
    /// path to the Cosmos IBC proto files
    ibc: PathBuf,

    #[argh(option, short = 'e')]
    /// path to the ethereum-light-client-types proto definitions
    ethereum_light_client_types: PathBuf,

    #[argh(option, short = 'o')]
    /// path to output the generated Rust sources into
    out: PathBuf,
}

impl CompileCmd {
    pub fn run(&self) {
        Self::compile_protos(&self.ibc, &self.ethereum_light_client_types, self.out.as_ref());
    }

    fn compile_protos(ibc_dir: &Path, elct_dir: &Path, out_dir: &Path) {
        // Remove old compiled files
        remove_dir_all(out_dir).unwrap_or_default();
        create_dir_all(out_dir).unwrap();

        println!(
            "[info ] Compiling optimism-elc .proto files to Rust into '{}'...",
            out_dir.display()
        );

        let root = env!("CARGO_MANIFEST_DIR");

        // Paths
        let proto_paths = [format!("{}/../proto/definitions", root)];

        let proto_includes_paths = [
            format!("{}/../proto/definitions", root),
            format!("{}/proto/definitions", elct_dir.display()),
            format!("{}/proto", ibc_dir.display()),
            format!("{}/third_party/proto", ibc_dir.display()),
        ];

        // List available proto files
        let mut protos: Vec<PathBuf> = vec![];
        for proto_path in &proto_paths {
            println!("Looking for proto files in {:?}", proto_path);
            protos.append(
                &mut WalkDir::new(proto_path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_type().is_file()
                            && e.path().extension().is_some()
                            && e.path().extension().unwrap() == "proto"
                    })
                    .map(|e| e.into_path())
                    .collect(),
            );
        }

        println!("Found the following protos:");
        // Show which protos will be compiled
        for proto in &protos {
            println!("\t-> {:?}", proto);
        }
        println!("[info ] Compiling..");

        // List available paths for dependencies
        let includes: Vec<PathBuf> = proto_includes_paths.iter().map(PathBuf::from).collect();
        let compilation = tonic_build::configure()
            .build_client(false)
            .build_server(false)
            .compile_well_known_types(true)
            .out_dir(out_dir)
            .extern_path(".ibc.core.client.v1", "::ibc_proto::ibc::core::client::v1")
            .extern_path(".cosmos.upgrade.v1beta1", "::ibc_proto::cosmos::upgrade::v1beta1")
            .extern_path(".ibc.lightclients.ethereum.v1.TrustedSyncCommittee", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::TrustedSyncCommittee")
            .extern_path(".ibc.lightclients.ethereum.v1.ForkParameters", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::ForkParameters")
            .extern_path(".ibc.lightclients.ethereum.v1.Fraction", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::Fraction")
            .extern_path(".ibc.lightclients.ethereum.v1.Fork", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::Fork")
            .extern_path(".ibc.lightclients.ethereum.v1.ForkSpec", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::ForkSpec")
            .extern_path(".ibc.lightclients.ethereum.v1.ConsensusUpdate", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::ConsensusUpdate")
            .extern_path(".ibc.lightclients.ethereum.v1.SyncCommittee", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::SyncCommittee")
            .extern_path(".ibc.lightclients.ethereum.v1.SyncAggregate", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::SyncAggregate")
            .extern_path(".ibc.lightclients.ethereum.v1.ExecutionUpdate", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::ExecutionUpdate")
            .extern_path(".ibc.lightclients.ethereum.v1.AccountUpdate", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::AccountUpdate")
            .extern_path(".ibc.lightclients.ethereum.v1.BeaconBlockHeader", "::ethereum_light_client_proto::ibc::lightclients::ethereum::v1::BeaconBlockHeader")
            .compile(&protos, &includes);

        match compilation {
            Ok(_) => {
                println!("Successfully compiled proto files");
            }
            Err(e) => {
                println!("Failed to compile:{:?}", e.to_string());
                process::exit(1);
            }
        }
    }
}
