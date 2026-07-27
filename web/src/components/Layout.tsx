import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { Button, cn } from "./ui";

const nav = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/health", label: "Health" },
  { to: "/policy", label: "Policy" },
  { to: "/objects", label: "Objects" },
  { to: "/logs", label: "Logs" },
  { to: "/audit", label: "Audit" },
  { to: "/settings", label: "Settings" },
  { to: "/client-setup", label: "Client setup" },
];

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="flex min-h-full bg-slate-50">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-slate-200 bg-white">
        <div className="border-b border-slate-100 px-5 py-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-brand-600">
            WSP
          </div>
          <div className="mt-0.5 text-sm font-semibold text-slate-900">
            Web Security Platform
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "block rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-brand-50 text-brand-800"
                    : "text-slate-600 hover:bg-slate-50 hover:text-slate-900",
                )
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-100 p-4">
          <div className="truncate text-sm font-medium text-slate-800">
            {user?.display_name || user?.username}
          </div>
          <div className="truncate text-xs text-slate-500">{user?.role}</div>
          <Button
            variant="outline"
            size="sm"
            className="mt-3 w-full"
            onClick={async () => {
              await logout();
              navigate("/login");
            }}
          >
            Sign out
          </Button>
        </div>
      </aside>
      <main className="min-w-0 flex-1">
        <div className="mx-auto max-w-6xl px-6 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
