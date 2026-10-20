//! Release verification before anything runs (SRS SR-7-2, FR-20.12,
//! FR-20.13).
//!
//! The same checks `install.sh` and `smcpctl upgrade` make, with the same
//! trust roots: the minisign signature of `smcp_<version>_checksums.txt`
//! with the release key embedded at build time (the key of `SECURITY.md`
//! and `install.sh`), its signed trusted comment naming that file, the
//! SHA-256 of each downloaded file against the verified checksum file and,
//! when `cosign` is installed, the checksum file's Sigstore bundle against
//! the release workflow identity. A release whose signed version is not
//! newer than the installed one is refused, so an old signed release with
//! known flaws cannot be replayed. Any failed check removes what was
//! downloaded and names the check.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;

use crate::release::{self, Http, Release};

/// The minisign release key (key ID 064FAC0C64ACCED0). A test keeps it
/// equal to the key in `install.sh`, `SECURITY.md` and
/// `cmd/smcpctl/release.go`.
pub const RELEASE_PUBLIC_KEY: &str = "RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq";
/// The certificate identity of the release workflow, as `install.sh` checks it.
pub const WORKFLOW_IDENTITY_REGEXP: &str =
    "^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@";
pub const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const COSIGN_TIMEOUT: Duration = Duration::from_secs(120);

/// The check that failed, named in the error the user sees
/// (`UPDATE_VERIFY_FAILED`, `UPDATE_NOT_NEWER` in the message catalogue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// The release is not newer than the installed version.
    Version,
    /// The release does not have the files this installation needs.
    Files,
    /// A download failed.
    Download,
    /// The minisign signature of the checksum file or its trusted comment.
    Signature,
    /// The Sigstore bundle, checked with cosign.
    Sigstore,
    /// A file's SHA-256 against the checksum file.
    Checksum,
}

impl Check {
    /// The name shown in the message: "did not pass the {check} check".
    pub fn name(self) -> &'static str {
        match self {
            Check::Version => "version",
            Check::Files => "release files",
            Check::Download => "download",
            Check::Signature => "minisign signature",
            Check::Sigstore => "Sigstore bundle",
            Check::Checksum => "SHA-256 checksum",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub check: Check,
    pub detail: String,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} check failed: {}", self.check.name(), self.detail)
    }
}

fn fail<T>(check: Check, detail: impl Into<String>) -> Result<T, VerifyError> {
    Err(VerifyError {
        check,
        detail: detail.into(),
    })
}

/// `smcp_<version>_checksums.txt`, the release's signed checksum file.
pub fn checksum_file_name(v: &Version) -> String {
    format!("smcp_{v}_checksums.txt")
}

/// SR-7-2: refuse a release that is not newer than the installed one.
pub fn check_newer(offered: &Version, installed: &Version) -> Result<(), VerifyError> {
    if offered > installed {
        Ok(())
    } else {
        fail(
            Check::Version,
            format!("version {offered} is not newer than the installed version {installed}"),
        )
    }
}

/// The verified checksum file: file name to lowercase hex SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sums(BTreeMap<String, String>);

impl Sums {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

/// Verifies the checksum file `name` with `body` against the minisign
/// signature `sig` and `pubkey`, requires the signed trusted comment to
/// name the file (so a signature cannot be moved to another release's
/// checksum file), and parses it.
pub fn verify_checksum_file(pubkey: &str, name: &str, body: &[u8], sig: &str) -> Result<Sums, VerifyError> {
    let pk = minisign_verify::PublicKey::from_base64(pubkey).map_err(|e| VerifyError {
        check: Check::Signature,
        detail: format!("release public key: {e}"),
    })?;
    let s = minisign_verify::Signature::decode(sig).map_err(|e| VerifyError {
        check: Check::Signature,
        detail: format!("{name}.minisig: {e}"),
    })?;
    // Prehashed signatures only, as minisign makes them; legacy ones are
    // refused.
    if let Err(e) = pk.verify(body, &s, false) {
        return fail(
            Check::Signature,
            format!("the minisign signature of {name} does not verify with the release key: {e}"),
        );
    }
    let want = format!("file:{name}");
    if !s.trusted_comment().split_whitespace().any(|t| t == want) {
        return fail(
            Check::Signature,
            format!("the signed trusted comment of {name}.minisig does not name {name}"),
        );
    }
    let text = std::str::from_utf8(body).map_err(|_| VerifyError {
        check: Check::Signature,
        detail: format!("{name} is not text"),
    })?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 2 {
            continue;
        }
        let file = f[1].trim_start_matches('*');
        let hex = f[0].to_ascii_lowercase();
        if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) && map.insert(file.to_string(), hex).is_some()
        {
            return fail(Check::Checksum, format!("{name} lists {file} twice"));
        }
    }
    Ok(Sums(map))
}

/// Lowercase hex SHA-256 of a file.
pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(p)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex(ctx.finish().as_ref()))
}

/// Lowercase hex SHA-256 of bytes.
pub fn sha256(b: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, b).as_ref())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Checks the file `name` at `path` against the verified checksum file.
pub fn check_file(sums: &Sums, name: &str, path: &Path) -> Result<(), VerifyError> {
    let Some(want) = sums.get(name) else {
        return fail(Check::Checksum, format!("the checksum file does not list {name}"));
    };
    let got = sha256_file(path).map_err(|e| VerifyError {
        check: Check::Checksum,
        detail: format!("{name}: {e}"),
    })?;
    if got != want {
        return fail(
            Check::Checksum,
            format!("checksum mismatch for {name}: expected {want}, got {got}"),
        );
    }
    Ok(())
}

/// The cosign check, a trait so tests can stand in for cosign.
pub trait Cosign: Send + Sync {
    /// Verifies the Sigstore `bundle` of `file` against the release
    /// workflow identity; `Err` carries cosign's output.
    fn verify_blob(&self, bundle: &Path, file: &Path) -> Result<(), String>;
}

/// The fixed argument vector of the cosign check (as in `install.sh`).
pub fn cosign_argv(cosign: &Path, bundle: &Path, file: &Path) -> Vec<String> {
    vec![
        cosign.display().to_string(),
        "verify-blob".into(),
        "--bundle".into(),
        bundle.display().to_string(),
        "--certificate-identity-regexp".into(),
        WORKFLOW_IDENTITY_REGEXP.into(),
        "--certificate-oidc-issuer".into(),
        OIDC_ISSUER.into(),
        file.display().to_string(),
    ]
}

/// The installed `cosign`, if any: the first executable `cosign` in the
/// fixed directories where package managers put it, then on `PATH`.
pub fn find_cosign(path_env: Option<&str>) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(p) = path_env {
        dirs.extend(std::env::split_paths(p).filter(|d| d.is_absolute()));
    }
    let exe = if cfg!(windows) { "cosign.exe" } else { "cosign" };
    dirs.into_iter().map(|d| d.join(exe)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    match std::fs::metadata(p) {
        #[cfg(unix)]
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            m.is_file() && m.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

/// Runs the installed cosign with the fixed argument vector.
pub struct SystemCosign(pub PathBuf);

impl Cosign for SystemCosign {
    fn verify_blob(&self, bundle: &Path, file: &Path) -> Result<(), String> {
        let argv = cosign_argv(&self.0, bundle, file);
        let r = crate::upgrade::run_fixed(&argv, None, COSIGN_TIMEOUT, &mut |_| {});
        if r.code == Some(0) {
            Ok(())
        } else {
            Err(r.summary())
        }
    }
}

/// The verified files of a release, in a directory only the user can read.
#[derive(Debug)]
pub struct Verified {
    pub dir: PathBuf,
    pub version: Version,
    /// The requested files, in the order requested.
    pub files: Vec<PathBuf>,
    /// Their SHA-256 digests from the verified checksum file.
    pub digests: Vec<String>,
    /// Whether the Sigstore bundle was checked (cosign installed).
    pub sigstore_checked: bool,
}

/// Downloads `wanted` files of `rel` into the new directory `dir` and
/// verifies them (SR-7-2), in this order: the release version against
/// `installed`, the minisign signature of the checksum file with `pubkey`,
/// the Sigstore bundle when `cosign` is given, then each file's SHA-256.
/// On any failure the directory is removed, so nothing can be installed
/// from it, and the failed check is returned.
pub fn fetch_verified(
    http: &dyn Http,
    rel: &Release,
    wanted: &[String],
    installed: &Version,
    pubkey: &str,
    cosign: Option<&dyn Cosign>,
    dir: &Path,
) -> Result<Verified, VerifyError> {
    check_newer(&rel.version, installed)?;
    create_private_dir(dir).map_err(|e| VerifyError {
        check: Check::Download,
        detail: format!("{}: {e}", dir.display()),
    })?;
    let r = fetch_verified_in(http, rel, wanted, pubkey, cosign, dir);
    if r.is_err() {
        let _ = std::fs::remove_dir_all(dir);
    }
    r
}

fn fetch_verified_in(
    http: &dyn Http,
    rel: &Release,
    wanted: &[String],
    pubkey: &str,
    cosign: Option<&dyn Cosign>,
    dir: &Path,
) -> Result<Verified, VerifyError> {
    let sums_name = checksum_file_name(&rel.version);
    let asset = |n: &str| {
        rel.asset(n).ok_or_else(|| VerifyError {
            check: Check::Files,
            detail: format!("release {} has no file {n}", rel.tag),
        })
    };
    let sums_asset = asset(&sums_name)?;
    let sig_asset = asset(&format!("{sums_name}.minisig"))?;
    let get = |a: &release::Asset, limit: u64| {
        http.get(&a.url, "application/octet-stream", limit)
            .map_err(|e| VerifyError {
                check: Check::Download,
                detail: format!("{}: {e}", a.name),
            })
    };
    let sums_body = get(sums_asset, release::MAX_SIGNATURE_BYTES)?;
    let sig_body = get(sig_asset, release::MAX_SIGNATURE_BYTES)?;
    let sig_text = String::from_utf8(sig_body).map_err(|_| VerifyError {
        check: Check::Signature,
        detail: format!("{}.minisig is not text", sums_name),
    })?;
    // 1. The minisign signature with the embedded key. The checksum file's
    // name carries the release version, and the signed comment names it,
    // so the version checked above is the signed one.
    let sums = verify_checksum_file(pubkey, &sums_name, &sums_body, &sig_text)?;
    let sums_path = dir.join(&sums_name);
    write_new(&sums_path, &sums_body)?;
    write_new(&dir.join(format!("{sums_name}.minisig")), sig_text.as_bytes())?;

    // 2. The Sigstore bundle, when cosign is installed.
    let mut sigstore_checked = false;
    if let Some(c) = cosign {
        let b = asset(&format!("{sums_name}.sigstore.json")).map_err(|_| VerifyError {
            check: Check::Sigstore,
            detail: format!("cosign is installed but release {} has no Sigstore bundle", rel.tag),
        })?;
        let body = get(b, release::MAX_SIGNATURE_BYTES)?;
        let bundle = dir.join(&b.name);
        write_new(&bundle, &body)?;
        c.verify_blob(&bundle, &sums_path).map_err(|e| VerifyError {
            check: Check::Sigstore,
            detail: format!(
                "cosign could not verify {} against the {} release workflow: {e}",
                b.name,
                release::REPO
            ),
        })?;
        sigstore_checked = true;
    }

    // 3. Each file's SHA-256 against the verified checksum file. A file not
    // listed is refused before it is downloaded.
    let mut files = Vec::new();
    let mut digests = Vec::new();
    for name in wanted {
        if sums.get(name).is_none() {
            return fail(Check::Checksum, format!("{sums_name} does not list {name}"));
        }
        let a = asset(name)?;
        let p = dir.join(name);
        http.download(&a.url, &p, release::MAX_ASSET_BYTES)
            .map_err(|e| VerifyError {
                check: Check::Download,
                detail: format!("{name}: {e}"),
            })?;
        check_file(&sums, name, &p)?;
        files.push(p);
        digests.push(sums.get(name).unwrap_or_default().to_string());
    }
    Ok(Verified {
        dir: dir.to_path_buf(),
        version: rel.version.clone(),
        files,
        digests,
        sigstore_checked,
    })
}

fn write_new(p: &Path, b: &[u8]) -> Result<(), VerifyError> {
    use std::io::Write;
    release::create_new(p)
        .and_then(|mut f| f.write_all(b))
        .map_err(|e| VerifyError {
            check: Check::Download,
            detail: format!("{}: {e}", p.display()),
        })
}

/// Creates `dir` (which must not exist) with mode 0700.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

#[cfg(test)]
pub(crate) mod testkey {
    //! A throwaway minisign key made for each test run. The release key's
    //! secret half is never used in tests.

    pub struct Key {
        pub public: String,
        kp: minisign::KeyPair,
    }

    impl Key {
        pub fn new() -> Key {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            Key {
                public: kp.pk.to_base64(),
                kp,
            }
        }

        /// A minisign signature box with this trusted comment.
        pub fn sign(&self, body: &[u8], trusted: &str) -> String {
            minisign::sign(Some(&self.kp.pk), &self.kp.sk, body, Some(trusted), None)
                .unwrap()
                .into_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkey::Key;
    use super::*;
    use crate::claims;
    use crate::release::testfeed::Server;
    use crate::release::NetHttp;
    use std::sync::Mutex;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/release-1.1.0");

    #[test]
    fn release_key_matches_install_sh_security_md_and_smcpctl() {
        claims::partial(&["SR-7-2"]);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let install = std::fs::read_to_string(root.join("install.sh")).unwrap();
        assert!(install.contains(&format!("PUBKEY=\"{RELEASE_PUBLIC_KEY}\"")));
        assert!(std::fs::read_to_string(root.join("SECURITY.md"))
            .unwrap()
            .contains(RELEASE_PUBLIC_KEY));
        assert!(std::fs::read_to_string(root.join("cmd/smcpctl/release.go"))
            .unwrap()
            .contains(&format!("releasePublicKey = \"{RELEASE_PUBLIC_KEY}\"")));
        assert!(install.contains(
            WORKFLOW_IDENTITY_REGEXP
                .replace("ethan03805/Secure-MCP-Gateway", "$REPO")
                .as_str()
        ));
    }

    /// The embedded release key verifies the published v1.1.0 checksum
    /// file (fixture copied from the release) and refuses a changed line.
    #[test]
    fn real_release_signature_verifies_with_the_embedded_key() {
        claims::partial(&["SR-7-2"]);
        let name = "smcp_1.1.0_checksums.txt";
        let body = std::fs::read(Path::new(FIXTURES).join(name)).unwrap();
        let sig = std::fs::read_to_string(Path::new(FIXTURES).join(format!("{name}.minisig"))).unwrap();
        let sums = verify_checksum_file(RELEASE_PUBLIC_KEY, name, &body, &sig).unwrap();
        assert_eq!(
            sums.get("smcp_1.1.0_darwin_arm64.tar.gz"),
            Some("b401ce434a9fec88783928d413f916ea370d01253454e42f26276c169a6fd953")
        );
        let mut bad = body.clone();
        bad[0] = if bad[0] == b'a' { b'b' } else { b'a' };
        assert_eq!(
            verify_checksum_file(RELEASE_PUBLIC_KEY, name, &bad, &sig)
                .unwrap_err()
                .check,
            Check::Signature
        );
        // The signature names its own file: it does not verify another name.
        assert_eq!(
            verify_checksum_file(RELEASE_PUBLIC_KEY, "smcp_9.9.9_checksums.txt", &body, &sig)
                .unwrap_err()
                .check,
            Check::Signature
        );
    }

    #[test]
    fn version_rule_refuses_equal_and_older() {
        claims::partial(&["SR-7-2"]);
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(check_newer(&v("1.3.1"), &v("1.3.0")).is_ok());
        assert!(check_newer(&v("1.3.0"), &v("1.3.0-rc.2")).is_ok());
        assert_eq!(check_newer(&v("1.3.0"), &v("1.3.0")).unwrap_err().check, Check::Version);
        assert_eq!(check_newer(&v("1.2.9"), &v("1.3.0")).unwrap_err().check, Check::Version);
    }

    #[test]
    fn cosign_argv_is_fixed() {
        claims::partial(&["SR-7-2"]);
        let a = cosign_argv(
            Path::new("/usr/bin/cosign"),
            Path::new("/d/b.json"),
            Path::new("/d/s.txt"),
        );
        assert_eq!(
            a,
            [
                "/usr/bin/cosign",
                "verify-blob",
                "--bundle",
                "/d/b.json",
                "--certificate-identity-regexp",
                "^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@",
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "/d/s.txt"
            ]
        );
    }

    /// The installed cosign, when there is one, verifies the published
    /// v1.1.0 Sigstore bundle with the workflow identity and refuses a
    /// changed bundle. It needs network access for the Sigstore trust root,
    /// so a failure to reach it is reported, not hidden.
    #[test]
    fn real_cosign_with_the_release_bundle() {
        claims::partial(&["SR-7-2"]);
        let Some(c) = find_cosign(std::env::var("PATH").ok().as_deref()) else {
            println!("cosign is not installed; skipped");
            return;
        };
        let dir = tmp("cosign");
        let name = "smcp_1.1.0_checksums.txt";
        let sums = dir.join(name);
        std::fs::copy(Path::new(FIXTURES).join(name), &sums).unwrap();
        let bundle = dir.join(format!("{name}.sigstore.json"));
        std::fs::copy(Path::new(FIXTURES).join(format!("{name}.sigstore.json")), &bundle).unwrap();
        let cosign = SystemCosign(c);
        match cosign.verify_blob(&bundle, &sums) {
            Ok(()) => {}
            Err(e) if e.contains("dial tcp") || e.contains("no such host") || e.contains("TUF") => {
                println!("cosign could not reach the Sigstore trust root; skipped: {e}");
                std::fs::remove_dir_all(&dir).unwrap();
                return;
            }
            Err(e) => panic!("cosign refused the release bundle: {e}"),
        }
        // The same bundle does not verify a changed checksum file.
        std::fs::write(&sums, b"changed\n").unwrap();
        assert!(cosign.verify_blob(&bundle, &sums).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    pub(crate) fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "smcp-desktop-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A stand-in for cosign that records its calls and answers as told.
    struct FakeCosign {
        ok: bool,
        calls: Mutex<Vec<(PathBuf, PathBuf)>>,
    }
    impl Cosign for FakeCosign {
        fn verify_blob(&self, bundle: &Path, file: &Path) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push((bundle.to_path_buf(), file.to_path_buf()));
            if self.ok {
                Ok(())
            } else {
                Err("Error: none of the expected identities matched".into())
            }
        }
    }

    /// A signed test release on a local feed.
    struct Feed {
        srv: Server,
        key: Key,
    }

    const INSTALLER: &str = "smcp_1.4.0_darwin_arm64.pkg";

    impl Feed {
        /// Publishes version `v` with one installer, signed with `signer`
        /// (default: the feed's key) and listed with `listed` as its digest.
        fn publish(&self, v: &str, installer: &[u8], listed: Option<String>, signer: Option<&Key>) -> Release {
            let sums_name = format!("smcp_{v}_checksums.txt");
            let inst = format!("smcp_{v}_darwin_arm64.pkg");
            let digest = listed.unwrap_or_else(|| sha256(installer));
            let sums = format!("{digest}  {inst}\n{}  smcp_{v}_linux_amd64.tar.gz\n", sha256(b"other"));
            let sig = signer
                .unwrap_or(&self.key)
                .sign(sums.as_bytes(), &format!("smcp {v} file:{sums_name}"));
            self.srv.put(&format!("/dl/{v}/{sums_name}"), sums);
            self.srv.put(&format!("/dl/{v}/{sums_name}.minisig"), sig);
            self.srv.put(&format!("/dl/{v}/{sums_name}.sigstore.json"), "{}");
            self.srv.put(&format!("/dl/{v}/{inst}"), installer.to_vec());
            let names = [
                sums_name.clone(),
                format!("{sums_name}.minisig"),
                format!("{sums_name}.sigstore.json"),
                inst,
            ];
            let doc = serde_json::json!({
                "tag_name": format!("v{v}"),
                "html_url": self.srv.url(&format!("/notes/v{v}")),
                "assets": names.iter().map(|n| serde_json::json!({
                    "name": n, "browser_download_url": self.srv.url(&format!("/dl/{v}/{n}")), "size": 1
                })).collect::<Vec<_>>()
            });
            self.srv.put("/latest", doc.to_string());
            release::latest(&NetHttp, &url::Url::parse(&self.srv.url("/latest")).unwrap())
                .unwrap()
                .unwrap()
        }
    }

    fn feed() -> Feed {
        Feed {
            srv: Server::start(),
            key: Key::new(),
        }
    }

    /// SR-7-2 V through a locally served test feed signed with a throwaway
    /// key: an installer with a modified byte, a checksum file with a
    /// modified line, a checksum file signed by another key, a bad
    /// Sigstore bundle with cosign installed, and an older correctly
    /// signed release are each refused with the failed check named and
    /// nothing left to install; a correct newer release is verified.
    #[test]
    fn test_feed_refuses_each_tampered_release_and_accepts_a_good_one() {
        claims::partial(&["SR-7-2", "FR-20.13"]);
        let f = feed();
        let installed = Version::new(1, 3, 0);
        let good = b"installer bytes of 1.4.0".to_vec();
        let wanted = vec![INSTALLER.to_string()];
        let base = tmp("verify");
        let run = |rel: &Release, cosign: Option<&dyn Cosign>, key: &str, tag: &str| {
            let dir = base.join(tag);
            let r = fetch_verified(&NetHttp, rel, &wanted, &installed, key, cosign, &dir);
            if r.is_err() {
                assert!(!dir.exists(), "{tag}: the download directory was not removed");
            }
            r
        };

        // A correct newer release.
        let rel = f.publish("1.4.0", &good, None, None);
        let cosign_ok = FakeCosign {
            ok: true,
            calls: Mutex::default(),
        };
        let v = run(&rel, Some(&cosign_ok), &f.key.public, "good").unwrap();
        assert_eq!(v.version.to_string(), "1.4.0");
        assert!(v.sigstore_checked);
        assert_eq!(std::fs::read(&v.files[0]).unwrap(), good);
        assert_eq!(cosign_ok.calls.lock().unwrap().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&v.dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(
                std::fs::metadata(&v.files[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Without cosign the Sigstore bundle is not checked; the rest is.
        assert!(!run(&rel, None, &f.key.public, "nocosign").unwrap().sigstore_checked);

        // An installer with a modified byte.
        let mut modified = good.clone();
        modified[0] ^= 1;
        let rel = f.publish("1.4.0", &modified, Some(sha256(&good)), None);
        assert_eq!(
            run(&rel, None, &f.key.public, "byte").unwrap_err().check,
            Check::Checksum
        );

        // A checksum file with a modified line (the signature no longer matches).
        let rel = f.publish("1.4.0", &good, None, None);
        let sums_path = "/dl/1.4.0/smcp_1.4.0_checksums.txt";
        let body = f.srv.files.lock().unwrap()[sums_path].clone();
        let mut text = String::from_utf8(body).unwrap();
        text = text.replacen(&sha256(&good), &sha256(&modified), 1);
        f.srv.put(sums_path, text);
        assert_eq!(
            run(&rel, None, &f.key.public, "line").unwrap_err().check,
            Check::Signature
        );

        // A checksum file signed by another key.
        let other = Key::new();
        let rel = f.publish("1.4.0", &good, None, Some(&other));
        assert_eq!(
            run(&rel, None, &f.key.public, "key").unwrap_err().check,
            Check::Signature
        );

        // A bad Sigstore bundle with cosign installed.
        let rel = f.publish("1.4.0", &good, None, None);
        let cosign_bad = FakeCosign {
            ok: false,
            calls: Mutex::default(),
        };
        let e = run(&rel, Some(&cosign_bad), &f.key.public, "sigstore").unwrap_err();
        assert_eq!(e.check, Check::Sigstore);
        assert!(e.detail.contains("none of the expected identities"));

        // An older, correctly signed release, and the same version.
        let old = f.publish("1.2.0", b"old installer", None, None);
        assert_eq!(
            fetch_verified(
                &NetHttp,
                &old,
                &["smcp_1.2.0_darwin_arm64.pkg".into()],
                &installed,
                &f.key.public,
                None,
                &base.join("old")
            )
            .unwrap_err()
            .check,
            Check::Version
        );
        assert!(!base.join("old").exists(), "nothing is downloaded for an older release");
        let same = f.publish("1.3.0", b"same", None, None);
        assert_eq!(
            fetch_verified(
                &NetHttp,
                &same,
                &["smcp_1.3.0_darwin_arm64.pkg".into()],
                &installed,
                &f.key.public,
                None,
                &base.join("same")
            )
            .unwrap_err()
            .check,
            Check::Version
        );

        // A release document that claims a newer version but serves an
        // older release's signed checksum file: the signed name does not
        // match, so the replay is refused.
        let rel_old = f.publish("1.2.0", b"old installer", None, None);
        let mut replay = rel_old.clone();
        replay.version = Version::new(1, 9, 0);
        replay.tag = "v1.9.0".into();
        for a in &mut replay.assets {
            a.name = a.name.replace("1.2.0", "1.9.0");
        }
        let e = fetch_verified(
            &NetHttp,
            &replay,
            &["smcp_1.9.0_darwin_arm64.pkg".into()],
            &installed,
            &f.key.public,
            None,
            &base.join("replay"),
        )
        .unwrap_err();
        assert_eq!(e.check, Check::Signature, "{e}");

        // A file the checksum file does not list is never downloaded.
        let rel = f.publish("1.4.0", &good, None, None);
        let e = fetch_verified(
            &NetHttp,
            &rel,
            &["smcp_1.4.0_other.pkg".into()],
            &installed,
            &f.key.public,
            None,
            &base.join("unlisted"),
        )
        .unwrap_err();
        assert_eq!(e.check, Check::Checksum);

        // The real release key does not accept the throwaway key's release.
        let rel = f.publish("1.4.0", &good, None, None);
        assert_eq!(
            run(&rel, None, RELEASE_PUBLIC_KEY, "realkey").unwrap_err().check,
            Check::Signature
        );

        std::fs::remove_dir_all(&base).unwrap();
    }
}
