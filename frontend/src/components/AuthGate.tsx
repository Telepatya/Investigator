import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { LogIn, ShieldAlert } from "lucide-react";
import { api, type AuthBootstrap } from "../lib/api";

interface AuthContextValue {
  auth: AuthBootstrap | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

import { createContext, useContext } from "react";

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthBootstrap | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setAuth(await api.authBootstrap());
    } catch {
      setAuth(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const handler = () => {
      setAuth((current) => current ? { ...current, authenticated: false, user: null } : current);
    };
    window.addEventListener("investigator:auth-required", handler);
    return () => window.removeEventListener("investigator:auth-required", handler);
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setAuth((current) => current ? { ...current, authenticated: false, user: null } : current);
    }
  }, []);

  const value = useMemo(() => ({ auth, loading, refresh, logout }), [auth, loading, refresh, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}

export function AuthGate({ children }: { children: ReactNode }) {
  const { auth, loading } = useAuth();
  if (loading) return <AuthStatus title="Checking access" message="Loading secure session…" />;
  if (!auth) return <AuthStatus title="Unable to check access" message="The Investigator backend is unavailable." error />;
  if (!auth.enabled) return <>{children}</>;
  if (!auth.configured) {
    return <AuthStatus title="Single sign-on is unavailable" message="The server administrator must complete the OIDC environment configuration." error />;
  }
  if (!auth.authenticated) return <LoginScreen loginUrl={auth.login_url} />;
  return <>{children}</>;
}

function LoginScreen({ loginUrl }: { loginUrl: string | null }) {
  const returnPath = useMemo(() => {
    const value = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    return value.startsWith("/") && !value.startsWith("//") ? value : "/";
  }, []);
  const login = () => {
    if (!loginUrl) return;
    const separator = loginUrl.includes("?") ? "&" : "?";
    window.location.assign(`${loginUrl}${separator}return_to=${encodeURIComponent(returnPath)}`);
  };
  return (
    <AuthStatus
      title="Sign in to Investigator"
      message="Use your organization account to access cases, rules, and reverse projects."
      action={<button className="btn-primary btn" onClick={login} disabled={!loginUrl}><LogIn size={17} /> Sign in with organization SSO</button>}
    />
  );
}

function AuthStatus({ title, message, error, action }: { title: string; message: string; error?: boolean; action?: ReactNode }) {
  return (
    <main className="grid min-h-screen place-items-center bg-base-900 px-6 text-center text-ink-100">
      <section className="card max-w-lg space-y-4 p-8">
        {error ? <ShieldAlert className="mx-auto text-sev-high" size={36} /> : <div className="mx-auto h-3 w-3 animate-pulse rounded-full bg-accent-blue" />}
        <h1 className="text-xl font-bold">{title}</h1>
        <p className="text-sm text-ink-300">{message}</p>
        {action}
      </section>
    </main>
  );
}
