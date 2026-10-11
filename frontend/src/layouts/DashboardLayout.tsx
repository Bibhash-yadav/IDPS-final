
import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  Bot,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  Shield,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import {
  NavLink,
  Outlet,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const navigation = [
  { label: "Dashboard", path: "/dashboard", icon: LayoutDashboard },
  { label: "URL Checker", path: "/url-checker", icon: FileSearch },
  { label: "Threats", path: "/threats", icon: Shield },
  { label: "Security Events", path: "/events", icon: Activity },
  { label: "Analytics", path: "/analytics", icon: BarChart3 },
  { label: "Protection", path: "/protection", icon: ShieldCheck },
  { label: "AI Assistant", path: "/ai-assistant", icon: Bot },
  { label: "Alerts", path: "/alerts", icon: Bell },
  { label: "Settings", path: "/settings", icon: Settings },
  { label: "Profile", path: "/profile", icon: UserRound },
];

export default function DashboardLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  const currentPage =
    navigation.find((item) => item.path === location.pathname)?.label ??
    "Security Center";

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="min-h-screen bg-[#080d18] text-slate-100">
      {mobileOpen && (
        <button
          aria-label="Close navigation menu"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/70 lg:hidden"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-slate-800 bg-[#0c1321] transition-all duration-200 ${
          collapsed ? "w-20" : "w-64"
        } ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        } lg:translate-x-0`}
      >
        <div className="flex h-20 items-center justify-between border-b border-slate-800 px-4">
          <button
            onClick={() => navigate("/dashboard")}
            className="flex min-w-0 items-center gap-3 text-left"
            title="IDPS Shield home"
          >
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-400">
              <ShieldCheck size={24} />
            </span>

            {!collapsed && (
              <span>
                <span className="block font-bold text-white">IDPS Shield</span>
                <span className="block text-xs text-slate-500">
                  Cyber Defense
                </span>
              </span>
            )}
          </button>

          <button
            onClick={() => setMobileOpen(false)}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 lg:hidden"
            aria-label="Close sidebar"
          >
            <X size={20} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-5">
          {!collapsed && (
            <p className="mb-3 px-3 text-xs font-semibold tracking-widest text-slate-500">
              SECURITY CENTER
            </p>
          )}

          <nav className="space-y-1">
            {navigation.map(({ label, path, icon: Icon }) => (
              <NavLink
                key={path}
                to={path}
                title={collapsed ? label : undefined}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-3 text-sm transition ${
                    isActive
                      ? "bg-cyan-400/10 font-semibold text-cyan-300"
                      : "text-slate-400 hover:bg-slate-800/70 hover:text-white"
                  }`
                }
              >
                <Icon size={19} className="shrink-0" />
                {!collapsed && <span>{label}</span>}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="border-t border-slate-800 p-3">
          <div className="mb-3 flex items-center gap-3 rounded-lg bg-slate-800/50 p-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-cyan-400/10 text-cyan-300">
              <UserRound size={18} />
            </span>

            {!collapsed && (
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-white">
                  {user?.name ?? "User"}
                </p>
                <p className="truncate text-xs text-slate-400">
                  {user?.email ?? ""}
                </p>
              </div>
            )}
          </div>

          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm text-slate-400 hover:bg-red-500/10 hover:text-red-300"
          >
            <LogOut size={19} />
            {!collapsed && "Logout"}
          </button>

          <button
            onClick={() => setCollapsed((value) => !value)}
            className="mt-1 hidden w-full items-center justify-center rounded-lg py-2 text-slate-500 hover:bg-slate-800 hover:text-white lg:flex"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          </button>
        </div>
      </aside>

      <div className={`min-h-screen transition-[padding] duration-200 ${collapsed ? "lg:pl-20" : "lg:pl-64"}`}>
        <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-slate-800 bg-[#080d18]/95 px-4 backdrop-blur md:px-8">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="rounded-lg border border-slate-800 p-2 text-slate-300 hover:bg-slate-800 lg:hidden"
              aria-label="Open navigation menu"
            >
              <Menu size={20} />
            </button>

            <div>
              <h1 className="font-semibold text-white">{currentPage}</h1>
              <p className="hidden text-xs text-slate-500 sm:block">
                Intelligent Cyber Defense System
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-400 sm:flex">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              API monitoring
            </div>

            <button
              onClick={() => navigate("/alerts")}
              aria-label="View alerts"
              className="rounded-lg border border-slate-800 p-2.5 text-slate-400 hover:bg-slate-800 hover:text-white"
            >
              <AlertTriangle size={19} />
            </button>
          </div>
        </header>

        <div className="min-h-[calc(100vh-5rem)]">
          <Outlet />
        </div>

        <footer className="border-t border-slate-800 px-5 py-4 text-center text-xs text-slate-600">
          IDPS Shield · Intelligent Cyber Defense · Security analysis may be incomplete
        </footer>
      </div>
    </div>
  );
}
