//! The release feed (SRS FR-20.11, X-16): finding a newer stable release
//! on the project's GitHub Releases, and downloading its files.
//!
//! The update check is the only network request the application makes on
//! its own. It is an anonymous HTTPS GET of one document: no cookies, no
//! credentials, no query string, a fixed `User-Agent` without a version and
//! no installation data. Automatic checks run at most once every 24 hours
//! and not at all when they are off in Settings; the time of the last
//! attempt is the only thing stored. Everything the feed returns is
//! untrusted until `verify` has checked it against the release key.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use semver::Version;
use serde::Deserialize;
use url::Url;

/// The canonical repository; its release workflow signs every release.
pub const REPO: &str = "ethan03805/Secure-MCP-Gateway";
/// The releases document: the newest release that is neither a draft nor
/// a prerelease.
pub const DEFAULT_FEED: &str = "https://api.github.com/repos/ethan03805/Secure-MCP-Gateway/releases/latest";
/// Points the application at another feed, for testing a release
/// candidate (FR-20.11 V). Verification still uses the embedded release
/// key, so another feed can offer only releases the project signed.
pub const FEED_ENV: &str = "SMCP_DESKTOP_RELEASE_FEED";
/// The fixed `User-Agent`. GitHub refuses requests without one; it carries
/// no version, so it does not identify the installation.
pub const USER_AGENT: &str = "smcp-desktop";
/// FR-20.11: at most one automatic check every 24 hours.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Bounds of what the application reads from the network.
pub const MAX_FEED_BYTES: u64 = 2 << 20;
pub const MAX_SIGNATURE_BYTES: u64 = 64 << 10;
pub const MAX_ASSET_BYTES: u64 = 1 << 30;
const FEED_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// The file in the application's configuration directory that holds the
/// time of the last update check, in seconds since 1970.
pub const LAST_CHECK_FILE: &str = "update-check";

/// One file of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: Url,
    pub size: u64,
}

/// A stable release offered by the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    pub tag: String,
    /// The release notes page, opened in the default browser.
    pub notes_url: Url,
    pub assets: Vec<Asset>,
}

impl Release {
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

/// Why the feed could not be read or used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    /// The network request failed (offline, DNS, TLS, HTTP status).
    Network(String),
    /// The document is not a release document the application accepts.
    Invalid(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::Network(m) => write!(f, "network: {m}"),
            FeedError::Invalid(m) => write!(f, "release document: {m}"),
        }
    }
}

/// Whether the application may fetch `u`: HTTPS, or plain HTTP to a
/// loopback address (a local test feed), never with user information.
pub fn allowed_url(u: &Url) -> bool {
    if !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => u.host().is_some(),
        "http" => match u.host() {
            Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    }
}

/// The feed URL: the canonical one, or `SMCP_DESKTOP_RELEASE_FEED`.
pub fn feed_url(env: Option<&str>) -> Result<Url, FeedError> {
    let s = env.filter(|s| !s.trim().is_empty()).unwrap_or(DEFAULT_FEED);
    let u = Url::parse(s.trim()).map_err(|e| FeedError::Invalid(format!("feed URL: {e}")))?;
    if !allowed_url(&u) || u.query().is_some() || u.fragment().is_some() {
        return Err(FeedError::Invalid(format!("feed URL {u} is not allowed")));
    }
    Ok(u)
}

#[derive(Deserialize)]
struct RawAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize)]
struct RawRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<RawAsset>,
}

/// A release file name: one path segment of ordinary characters.
fn plain_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 200
        && n != "."
        && n != ".."
        && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c))
}

/// Parses the releases document. Returns `None` for a draft, a prerelease
/// or a version with a prerelease part: only stable releases are offered.
pub fn parse_release(body: &[u8]) -> Result<Option<Release>, FeedError> {
    let raw: RawRelease = serde_json::from_slice(body).map_err(|e| FeedError::Invalid(e.to_string()))?;
    let num = raw
        .tag_name
        .strip_prefix('v')
        .ok_or_else(|| FeedError::Invalid(format!("tag {:?} does not start with v", raw.tag_name)))?;
    let version = Version::parse(num).map_err(|e| FeedError::Invalid(format!("tag {:?}: {e}", raw.tag_name)))?;
    if raw.draft || raw.prerelease || !version.pre.is_empty() {
        return Ok(None);
    }
    let notes_url = Url::parse(&raw.html_url).map_err(|e| FeedError::Invalid(format!("html_url: {e}")))?;
    if !allowed_url(&notes_url) {
        return Err(FeedError::Invalid(format!(
            "release notes URL {notes_url} is not allowed"
        )));
    }
    let mut assets: Vec<Asset> = Vec::new();
    for a in raw.assets {
        if !plain_name(&a.name) {
            return Err(FeedError::Invalid(format!("asset name {:?}", a.name)));
        }
        if assets.iter().any(|b| b.name == a.name) {
            return Err(FeedError::Invalid(format!("asset {} is listed twice", a.name)));
        }
        let url = Url::parse(&a.browser_download_url).map_err(|e| FeedError::Invalid(format!("{}: {e}", a.name)))?;
        if !allowed_url(&url) {
            return Err(FeedError::Invalid(format!(
                "{}: download URL {url} is not allowed",
                a.name
            )));
        }
        assets.push(Asset {
            name: a.name,
            url,
            size: a.size,
        });
    }
    Ok(Some(Release {
        version,
        tag: raw.tag_name,
        notes_url,
        assets,
    }))
}

/// Network access, a trait so tests can count requests.
pub trait Http: Send + Sync {
    /// GETs `url` and returns at most `limit` bytes of its body.
    fn get(&self, url: &Url, accept: &str, limit: u64) -> Result<Vec<u8>, FeedError>;
    /// GETs `url` into the new file `dest`, at most `limit` bytes.
    fn download(&self, url: &Url, dest: &Path, limit: u64) -> Result<(), FeedError>;
}

/// The real client: ureq over rustls with the operating system's trust
/// store. It keeps no cookies, sends no credentials, asks for no
/// compression and follows at most five redirects, staying on HTTPS.
pub struct NetHttp;

impl NetHttp {
    fn agent(url: &Url, timeout: Duration) -> ureq::Agent {
        let https = url.scheme() == "https";
        let mut cfg = ureq::Agent::config_builder()
            .https_only(https)
            .user_agent(USER_AGENT)
            .accept_encoding("")
            .max_redirects(5)
            .save_redirect_history(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_global(Some(timeout))
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            );
        if !https {
            // A loopback test feed is never reached through a proxy.
            cfg = cfg.proxy(None);
        }
        cfg.build().into()
    }
}

fn net_err(e: ureq::Error) -> FeedError {
    FeedError::Network(e.to_string())
}

impl Http for NetHttp {
    fn get(&self, url: &Url, accept: &str, limit: u64) -> Result<Vec<u8>, FeedError> {
        if !allowed_url(url) {
            return Err(FeedError::Invalid(format!("{url} is not allowed")));
        }
        let mut resp = Self::agent(url, FEED_TIMEOUT)
            .get(url.as_str())
            .header("Accept", accept)
            .call()
            .map_err(net_err)?;
        resp.body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(net_err)
    }

    fn download(&self, url: &Url, dest: &Path, limit: u64) -> Result<(), FeedError> {
        if !allowed_url(url) {
            return Err(FeedError::Invalid(format!("{url} is not allowed")));
        }
        let mut resp = Self::agent(url, DOWNLOAD_TIMEOUT)
            .get(url.as_str())
            .header("Accept", "application/octet-stream")
            .call()
            .map_err(net_err)?;
        let mut reader = resp.body_mut().with_config().limit(limit).reader();
        let mut f = create_new(dest).map_err(|e| FeedError::Network(format!("{}: {e}", dest.display())))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).map_err(|e| FeedError::Network(e.to_string()))?;
            if n == 0 {
                break;
            }
            f.write_all(&buf[..n])
                .map_err(|e| FeedError::Network(format!("{}: {e}", dest.display())))?;
        }
        f.sync_all().map_err(|e| FeedError::Network(e.to_string()))
    }
}

/// Creates a new file readable only by the user.
pub fn create_new(p: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)
}

/// Reads the releases document and returns the stable release it names,
/// if any.
pub fn latest(http: &dyn Http, feed: &Url) -> Result<Option<Release>, FeedError> {
    let body = http.get(feed, "application/vnd.github+json", MAX_FEED_BYTES)?;
    parse_release(&body)
}

/// What a check found, relative to the installed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// A newer stable release.
    Newer(Release),
    /// No newer stable release; the newest stable version, if any.
    Latest(Option<Version>),
}

pub fn compare(r: Option<Release>, installed: &Version) -> Found {
    match r {
        Some(r) if r.version > *installed => Found::Newer(r),
        Some(r) => Found::Latest(Some(r.version)),
        None => Found::Latest(None),
    }
}

/// Whether an automatic check is due (FR-20.11): automatic checks on, and
/// no attempt in the last 24 hours. A last attempt in the future (the
/// clock was set back) makes the check due, so a wrong clock cannot stop
/// checks for good.
pub fn auto_due(enabled: bool, last: Option<SystemTime>, now: SystemTime) -> bool {
    if !enabled {
        return false;
    }
    match last {
        None => true,
        Some(t) => match now.duration_since(t) {
            Ok(d) => d >= CHECK_INTERVAL,
            Err(_) => true,
        },
    }
}

/// Reads the time of the last check from `dir`.
pub fn load_last_check(dir: &Path) -> Option<SystemTime> {
    let s = std::fs::read_to_string(dir.join(LAST_CHECK_FILE)).ok()?;
    let secs: u64 = s.trim().parse().ok()?;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Records the time of a check attempt, successful or not, so a host
/// without network makes one automatic attempt a day, not a loop.
pub fn save_last_check(dir: &Path, t: SystemTime) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let tmp = dir.join(format!("{LAST_CHECK_FILE}.tmp"));
    std::fs::write(&tmp, format!("{secs}\n"))?;
    std::fs::rename(tmp, dir.join(LAST_CHECK_FILE))
}

#[cfg(test)]
pub(crate) mod testfeed {
    //! A local release feed for tests: a loopback HTTP server that serves
    //! fixed bodies by path and records every request it receives.

    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    /// One received request: the request line and the header lines.
    #[derive(Debug, Clone)]
    pub struct Seen {
        pub line: String,
        pub headers: Vec<(String, String)>,
    }

    pub struct Server {
        pub base: String,
        pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        pub seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Server {
        pub fn start() -> Server {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
            let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
            let (f2, s2) = (files.clone(), seen.clone());
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let Ok(c) = c else { continue };
                    let (f3, s3) = (f2.clone(), s2.clone());
                    std::thread::spawn(move || serve(c, &f3, &s3));
                }
            });
            Server { base, files, seen }
        }

        pub fn put(&self, path: &str, body: impl Into<Vec<u8>>) {
            self.files.lock().unwrap().insert(path.to_string(), body.into());
        }

        pub fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base)
        }

        pub fn requests(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn serve(c: TcpStream, files: &Mutex<HashMap<String, Vec<u8>>>, seen: &Mutex<Vec<Seen>>) {
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut line = String::new();
        if r.read_line(&mut line).is_err() {
            return;
        }
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).is_err() || h.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = h.trim_end().split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let line = line.trim_end().to_string();
        let path = line.split(' ').nth(1).unwrap_or("").to_string();
        seen.lock().unwrap().push(Seen { line, headers });
        let body = files.lock().unwrap().get(&path).cloned();
        let mut w = c;
        let _ = match body {
            Some(b) => {
                let _ = write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                );
                w.write_all(&b)
            }
            None => w.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        };
        let _ = w.flush();
        let mut sink = [0u8; 1];
        let _ = r.read(&mut sink);
    }
}

#[cfg(test)]
mod tests {
    use super::testfeed::Server;
    use super::*;
    use crate::claims;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn doc(tag: &str, base: &str) -> String {
        serde_json::json!({
            "tag_name": tag,
            "html_url": format!("{base}/notes/{tag}"),
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "smcp_1.4.0_checksums.txt", "browser_download_url": format!("{base}/dl/smcp_1.4.0_checksums.txt"), "size": 10}
            ]
        })
        .to_string()
    }

    #[test]
    fn parses_a_stable_release_and_skips_prereleases() {
        claims::partial(&["FR-20.11"]);
        let r = parse_release(doc("v1.4.0", "https://github.com/x").as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(r.version, Version::new(1, 4, 0));
        assert_eq!(r.notes_url.as_str(), "https://github.com/x/notes/v1.4.0");
        assert_eq!(r.assets.len(), 1);
        assert!(parse_release(doc("v1.4.0-rc.1", "https://github.com/x").as_bytes())
            .unwrap()
            .is_none());
        let mut pre: serde_json::Value = serde_json::from_str(&doc("v1.4.0", "https://github.com/x")).unwrap();
        pre["prerelease"] = true.into();
        assert!(parse_release(pre.to_string().as_bytes()).unwrap().is_none());
        // Refused: no v prefix, an insecure remote URL, an asset name with
        // a path, a duplicate asset.
        assert!(parse_release(doc("1.4.0", "https://github.com/x").as_bytes()).is_err());
        assert!(parse_release(doc("v1.4.0", "http://example.com").as_bytes()).is_err());
        let mut bad: serde_json::Value = serde_json::from_str(&doc("v1.4.0", "https://github.com/x")).unwrap();
        bad["assets"][0]["name"] = "../x".into();
        assert!(parse_release(bad.to_string().as_bytes()).is_err());
        let mut dup: serde_json::Value = serde_json::from_str(&doc("v1.4.0", "https://github.com/x")).unwrap();
        let a = dup["assets"][0].clone();
        dup["assets"].as_array_mut().unwrap().push(a);
        assert!(parse_release(dup.to_string().as_bytes()).is_err());
    }

    #[test]
    fn only_https_or_loopback_http() {
        claims::partial(&["FR-20.11"]);
        for ok in [
            "https://api.github.com/repos/a/b/releases/latest",
            "http://127.0.0.1:9/x",
            "http://[::1]:9/x",
            "http://localhost:9/x",
        ] {
            assert!(allowed_url(&Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "http://example.com/x",
            "http://10.0.0.1/x",
            "https://user:pw@example.com/x",
            "file:///etc/passwd",
            "ftp://example.com/x",
        ] {
            assert!(!allowed_url(&Url::parse(bad).unwrap()), "{bad}");
        }
        assert_eq!(feed_url(None).unwrap().as_str(), DEFAULT_FEED);
        assert_eq!(feed_url(Some("")).unwrap().as_str(), DEFAULT_FEED);
        assert!(feed_url(Some("http://example.com/feed")).is_err());
        assert!(feed_url(Some("https://example.com/feed?id=1")).is_err());
    }

    #[test]
    fn schedule_is_at_most_once_a_day_and_off_when_disabled() {
        claims::partial(&["FR-20.11"]);
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(auto_due(true, None, t0));
        assert!(!auto_due(false, None, t0));
        assert!(!auto_due(true, Some(t0), t0 + Duration::from_secs(3600)));
        assert!(!auto_due(true, Some(t0), t0 + CHECK_INTERVAL - Duration::from_secs(1)));
        assert!(auto_due(true, Some(t0), t0 + CHECK_INTERVAL));
        assert!(!auto_due(false, Some(t0), t0 + CHECK_INTERVAL * 3));
        // A clock set back does not stop checks for good.
        assert!(auto_due(true, Some(t0), t0 - Duration::from_secs(10)));

        let dir = std::env::temp_dir().join(format!("smcp-desktop-lastcheck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(load_last_check(&dir), None);
        save_last_check(&dir, t0).unwrap();
        assert_eq!(load_last_check(&dir), Some(t0));
        assert_eq!(
            std::fs::read_to_string(dir.join(LAST_CHECK_FILE)).unwrap(),
            "1800000000\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Counts requests, for the schedule simulation below.
    struct Counting<'a>(&'a dyn Http, AtomicUsize);
    impl Http for Counting<'_> {
        fn get(&self, url: &Url, accept: &str, limit: u64) -> Result<Vec<u8>, FeedError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.get(url, accept, limit)
        }
        fn download(&self, url: &Url, dest: &Path, limit: u64) -> Result<(), FeedError> {
            self.0.download(url, dest, limit)
        }
    }

    /// FR-20.11 V against a local test feed: one automatic request in 24
    /// hours, a request on demand, the reported version and notes link,
    /// none with automatic checks off, and a request that carries no
    /// identifier, cookie, credential or installation data.
    #[test]
    fn check_against_a_local_feed_is_anonymous_and_scheduled() {
        claims::partial(&["FR-20.11"]);
        let srv = Server::start();
        srv.put("/repos/x/releases/latest", doc("v1.4.0", &srv.base));
        let feed = Url::parse(&srv.url("/repos/x/releases/latest")).unwrap();
        let http = Counting(&NetHttp, AtomicUsize::new(0));
        let installed = Version::new(1, 3, 0);

        // Simulated hours of a running application: an automatic check
        // whenever due, and one on demand at hour 5.
        let t0 = UNIX_EPOCH + Duration::from_secs(1_900_000_000);
        let mut last = None;
        let mut found = Vec::new();
        for hour in 0..30u64 {
            let now = t0 + Duration::from_secs(hour * 3600);
            if auto_due(true, last, now) {
                last = Some(now);
                found.push(compare(latest(&http, &feed).unwrap(), &installed));
            }
            if hour == 5 {
                found.push(compare(latest(&http, &feed).unwrap(), &installed));
            }
        }
        // Hours 0 and 24 automatically, hour 5 on demand.
        assert_eq!(http.1.load(Ordering::SeqCst), 3);
        match &found[0] {
            Found::Newer(r) => {
                assert_eq!(r.version.to_string(), "1.4.0");
                assert_eq!(r.notes_url.as_str(), srv.url("/notes/v1.4.0"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            compare(latest(&http, &feed).unwrap(), &Version::new(1, 4, 0)),
            Found::Latest(Some(Version::new(1, 4, 0)))
        );

        // Automatic checks off: no request in 30 days.
        let before = http.1.load(Ordering::SeqCst);
        for hour in 0..720u64 {
            assert!(!auto_due(false, None, t0 + Duration::from_secs(hour * 3600)));
        }
        assert_eq!(http.1.load(Ordering::SeqCst), before);

        // Each captured request is a plain GET of the document path with
        // only the headers HTTP and GitHub need.
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 4);
        for r in &reqs {
            assert_eq!(r.line, "GET /repos/x/releases/latest HTTP/1.1");
            let names: Vec<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
            for n in &names {
                assert!(["host", "user-agent", "accept"].contains(n), "unexpected header {n}");
            }
            let ua = &r.headers.iter().find(|(k, _)| k == "user-agent").unwrap().1;
            assert_eq!(ua, USER_AGENT, "the User-Agent carries no version");
        }
    }

    /// FR-20.11 V: offline, a check fails once with a network error and
    /// makes no further request on its own.
    #[test]
    fn offline_check_fails_once_without_a_loop() {
        claims::partial(&["FR-20.11"]);
        // A loopback port with no listener: connection refused.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let feed = Url::parse(&format!("http://127.0.0.1:{port}/releases/latest")).unwrap();
        let http = Counting(&NetHttp, AtomicUsize::new(0));
        match latest(&http, &feed) {
            Err(FeedError::Network(_)) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(http.1.load(Ordering::SeqCst), 1);
        // The failed attempt counts as the day's check.
        let now = SystemTime::now();
        assert!(!auto_due(true, Some(now), now + Duration::from_secs(60)));
    }

    #[test]
    fn downloads_are_bounded_and_new_files() {
        claims::partial(&["FR-20.13"]);
        let srv = Server::start();
        srv.put("/a", vec![7u8; 5000]);
        let dir = std::env::temp_dir().join(format!("smcp-desktop-dl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let u = Url::parse(&srv.url("/a")).unwrap();
        NetHttp.download(&u, &dir.join("a"), 10_000).unwrap();
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), vec![7u8; 5000]);
        // Never overwrites, never exceeds the limit, 404 is an error.
        assert!(NetHttp.download(&u, &dir.join("a"), 10_000).is_err());
        assert!(NetHttp.download(&u, &dir.join("b"), 100).is_err());
        assert!(NetHttp
            .download(&Url::parse(&srv.url("/none")).unwrap(), &dir.join("c"), 100)
            .is_err());
        assert!(NetHttp.get(&Url::parse(&srv.url("/a")).unwrap(), "*/*", 100).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
