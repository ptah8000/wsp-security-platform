import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Navigate, useLocation } from "react-router-dom";
import { ApiClientError, getSetupStatus, logout as apiLogout, me } from "./api";
import type { AdminUser, SetupStatus } from "./types";
import { Spinner } from "./components/ui";

type AuthState = {
  loading: boolean;
  user: AdminUser | null;
  setup: SetupStatus | null;
  refresh: () => Promise<void>;
  setUser: (u: AdminUser | null) => void;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<AdminUser | null>(null);
  const [setup, setSetup] = useState<SetupStatus | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const status = await getSetupStatus();
      setSetup(status);
      if (!status.setup_completed) {
        setUser(null);
        return;
      }
      try {
        const u = await me();
        setUser(u);
      } catch (err) {
        if (err instanceof ApiClientError && err.status === 401) {
          setUser(null);
        } else {
          setUser(null);
        }
      }
    } catch {
      setSetup(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      // ignore
    }
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ loading, user, setup, refresh, setUser, logout }),
    [loading, user, setup, refresh, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

/** Gate authenticated admin routes; redirect to setup or login as needed. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { loading, user, setup } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <Spinner label="Checking session…" />
      </div>
    );
  }

  if (setup && !setup.setup_completed) {
    return <Navigate to="/setup" replace />;
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return <>{children}</>;
}

/** Public routes that should bounce away when setup is incomplete or already logged in. */
export function PublicOnly({
  children,
  allowWhenSetupIncomplete = false,
}: {
  children: ReactNode;
  allowWhenSetupIncomplete?: boolean;
}) {
  const { loading, user, setup } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <Spinner label="Loading…" />
      </div>
    );
  }

  if (setup && !setup.setup_completed) {
    if (allowWhenSetupIncomplete) return <>{children}</>;
    return <Navigate to="/setup" replace />;
  }

  if (user) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

export function SetupOnly({ children }: { children: ReactNode }) {
  const { loading, setup } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <Spinner label="Loading setup…" />
      </div>
    );
  }

  if (setup?.setup_completed) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
