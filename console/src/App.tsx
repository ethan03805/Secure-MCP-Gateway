// Console shell: sign-in, the status strip with enforcement state and
// emergency stop, the navigation of the views the role may open, and the
// current view.
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, credentials, post, setCredentials, setUnauthorizedHandler, type Credentials, type Role } from "./api";
import { LiveProvider, useLive } from "./data";
import { EmergencyControl, HealthProvider, isStopped, useHealth } from "./health";
import { Link, navigate, useLocation } from "./router";
import { ThemeSelect } from "./theme";
import { ErrorBlock, Mono, StateLabel, toneOf } from "./ui";
import { viewFor, views, type ViewDef } from "./views/registry";

function SignIn({ onSignedIn, expired }: { onSignedIn: (c: Credentials) => void; expired: boolean }) {
  const [kind, setKind] = useState<Role>("administrator");
  const [user, setUser] = useState(kind === "administrator" ? "admin" : "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [bootstrap, setBootstrap] = useState(false);
  const [token, setToken] = useState("");
  const [newPw, setNewPw] = useState("");
  const [bootDone, setBootDone] = useState(false);
  useEffect(() => {
    document.title = "Sign in | Gateway console";
  }, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const path = kind === "administrator" ? "/admin/v1/login" : "/api/v1/approvals/login";
      const r = await post<{ token: string; expires_in: number }>(path, { username: user.trim(), password });
      onSignedIn({ token: r.token, role: kind, user: user.trim(), expiresAt: Date.now() + r.expires_in * 1000 });
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "client", String(err)));
    } finally {
      setBusy(false);
      setPassword("");
    }
  };
  const redeem = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("/admin/v1/bootstrap", { token: token.trim(), password: newPw });
      setBootDone(true);
      setBootstrap(false);
      setKind("administrator");
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "client", String(err)));
    } finally {
      setBusy(false);
      setNewPw("");
      setToken("");
    }
  };
  return (
    <main className="signin" id="main">
      <h1>Gateway console</h1>
      <p className="lede">Sign in to control this Secure MCP Gateway. The console talks only to the control API on this loopback address.</p>
      {expired && (
        <p className="notice notice-warn" role="status">
          Your sign-in ended. Sign in again to continue where you were.
        </p>
      )}
      {bootDone && (
        <p className="notice notice-ok" role="status">
          The administrator password is set. Sign in with it.
        </p>
      )}
      {!bootstrap ? (
        <form onSubmit={submit} aria-label="Sign in">
          <fieldset className="choice">
            <legend>Account</legend>
            <label>
              <input type="radio" name="kind" checked={kind === "administrator"} onChange={() => { setKind("administrator"); setUser("admin"); }} />
              Administrator
            </label>
            <label>
              <input type="radio" name="kind" checked={kind === "approver"} onChange={() => { setKind("approver"); setUser(""); }} />
              Approver (tool-call approvals only)
            </label>
          </fieldset>
          <label className="field">
            <span>Username</span>
            <input value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" required name="username" />
          </label>
          <label className="field">
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required name="password" />
          </label>
          {error && <ErrorBlock error={error} />}
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? "Signing in" : "Sign in"}
          </button>
          <p className="small">
            Session Approver accounts sign in only when a harness connects, on the Gateway's own sign-in page. First installation:{" "}
            <button type="button" className="link" onClick={() => { setBootstrap(true); setError(null); }}>
              set the administrator password with a bootstrap token
            </button>
            .
          </p>
        </form>
      ) : (
        <form onSubmit={redeem} aria-label="Set the administrator password">
          <p>
            <Mono>smcpctl bootstrap</Mono> without a password file prints a one-use bootstrap token that is valid for 24 hours. Enter it with the new
            administrator password (at least 12 characters).
          </p>
          <label className="field">
            <span>Bootstrap token</span>
            <input value={token} onChange={(e) => setToken(e.target.value)} required autoComplete="off" spellCheck={false} />
          </label>
          <label className="field">
            <span>New administrator password</span>
            <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} minLength={12} required autoComplete="new-password" />
          </label>
          {error && <ErrorBlock error={error} />}
          <div className="dialog-actions">
            <button type="button" onClick={() => setBootstrap(false)}>
              Back to sign-in
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              Set password
            </button>
          </div>
        </form>
      )}
    </main>
  );
}

function StatusStrip({ cred, onSignOut }: { cred: Credentials; onSignOut: () => void }) {
  const health = useHealth();
  const live = useLive();
  const h = health?.status === "ok" ? health.data : undefined;
  const stopped = isStopped(h);
  const cls = h ? (h.state === "fail-closed" ? "strip strip-bad" : h.state === "degraded" ? "strip strip-warn" : "strip") : "strip";
  return (
    <header className={cls} data-testid="status-strip">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <span className="strip-name">Secure MCP Gateway</span>
      {cred.role === "administrator" ? (
        h ? (
          <>
            <span className="strip-item" aria-live="polite">
              <span className="sr-only">Enforcement state: </span>
              <StateLabel tone={toneOf(h.state)}>{stopped ? "emergency stop" : h.state}</StateLabel>
            </span>
            <span className="strip-item">
              {h.profile}: <strong>{h.release_label}</strong>
            </span>
            <span className="strip-item">
              policy <Mono>{h.policy_revision ?? "none"}</Mono>
            </span>
            <span className="strip-item">
              <Mono>{h.sessions}</Mono> session{h.sessions === 1 ? "" : "s"}
            </span>
          </>
        ) : health?.status === "error" ? (
          <span className="strip-item">health unavailable: {health.error.message}</span>
        ) : (
          <span className="strip-item">reading health</span>
        )
      ) : (
        <span className="strip-item">approvals only</span>
      )}
      <span className="strip-item strip-live" title={live.lastEvent ? `last change ${live.lastEvent}` : undefined}>
        {live.connected ? "live" : "not live: refresh to update"}
      </span>
      <span className="strip-spacer" />
      {cred.role === "administrator" && <EmergencyControl compact />}
      <span className="strip-item">
        <Mono>{cred.role === "administrator" ? `admin:${cred.user}` : `approver:${cred.user}`}</Mono>
      </span>
      <button type="button" className="btn-quiet" onClick={onSignOut}>
        Sign out
      </button>
    </header>
  );
}

function Nav({ role, current }: { role: Role; current?: ViewDef }) {
  const allowed = views.filter((v) => v.roles.includes(role));
  const groups = [...new Set(allowed.map((v) => v.group))];
  return (
    <nav className="rail" aria-label="Views">
      {groups.map((g) => (
        <div key={g} className="rail-group">
          <h2>{g}</h2>
          <ul>
            {allowed
              .filter((v) => v.group === g)
              .map((v) => (
                <li key={v.path}>
                  <Link to={v.path} aria-current={current === v ? "page" : undefined}>
                    <span className="rail-code mono">{v.code ?? ""}</span>
                    {v.title}
                  </Link>
                </li>
              ))}
          </ul>
        </div>
      ))}
      <ThemeSelect />
    </nav>
  );
}

function Shell({ cred, onSignOut }: { cred: Credentials; onSignOut: () => void }) {
  const { path } = useLocation();
  const view = viewFor(path);
  const allowed = view && view.roles.includes(cred.role);
  useEffect(() => {
    // An approver landing on an administrator view goes to the approvals.
    if (cred.role === "approver" && (!view || !allowed) && path === "/") navigate("/approvals", true);
  }, [cred.role, view, allowed, path]);
  return (
    <HealthOrNot admin={cred.role === "administrator"}>
      <StatusStrip cred={cred} onSignOut={onSignOut} />
      <div className="layout">
        <Nav role={cred.role} current={view} />
        <main id="main" className="main">
          {!view ? (
            <>
              <h1 tabIndex={-1}>No such view</h1>
              <p className="empty">
                <Mono>{path}</Mono> is not a console view. <Link to={cred.role === "administrator" ? "/" : "/approvals"}>Open the start view</Link>.
              </p>
            </>
          ) : !allowed ? (
            <>
              <h1 tabIndex={-1}>{view.title}</h1>
              <p className="notice notice-bad" role="alert">
                The {cred.role} role cannot open this view. Sign in as an Administrator to use it.
              </p>
            </>
          ) : (
            view.render(path)
          )}
        </main>
      </div>
    </HealthOrNot>
  );
}

function HealthOrNot({ admin, children }: { admin: boolean; children: ReactNode }) {
  return admin ? <HealthProvider>{children}</HealthProvider> : <>{children}</>;
}

export function App() {
  const [cred, setCred] = useState<Credentials | null>(() => credentials());
  const [expired, setExpired] = useState(false);
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCredentials(null);
      setCred(null);
      setExpired(true);
    });
  }, []);
  useEffect(() => {
    if (!cred) return;
    const t = window.setTimeout(() => {
      setCredentials(null);
      setCred(null);
      setExpired(true);
    }, Math.max(0, cred.expiresAt - Date.now()));
    return () => window.clearTimeout(t);
  }, [cred]);
  const signOut = async () => {
    const c = credentials();
    if (c) {
      try {
        await post(c.role === "administrator" ? "/admin/v1/logout" : "/api/v1/approvals/logout", {});
      } catch {
        // The token is dropped locally either way.
      }
    }
    setCredentials(null);
    setCred(null);
    setExpired(false);
  };
  if (!cred) {
    return (
      <SignIn
        expired={expired}
        onSignedIn={(c) => {
          setCredentials(c);
          setCred(c);
          setExpired(false);
        }}
      />
    );
  }
  return (
    <LiveProvider key={cred.token}>
      <Shell cred={cred} onSignOut={() => void signOut()} />
    </LiveProvider>
  );
}
