
import { useEffect, useState } from "react";

import {
  Activity,
  BarChart3,
  Bell,
  Bot,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Settings,
  Shield,
  ShieldCheck,
  Sun,
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

  // Restore saved theme
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("idps-theme") || "dark";
    } catch {
      return "dark";
    }
  });

  // Apply theme globally and save preference
  useEffect(() => {
    document.documentElement.dataset.theme = theme;

    try {
      localStorage.setItem("idps-theme", theme);
    } catch {
      // Theme works for current session.
    }
  }, [theme]);

  const isDark = theme === "dark";

  const currentPage =
    navigation.find((item) => item.path === location.pathname)?.label ??
    "Security Center";

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  function toggleTheme() {
    setTheme((previous) =>
      previous === "dark" ? "light" : "dark"
    );
  }

  const sidebarWidth = collapsed
    ? "lg:pl-[92px]"
    : "lg:pl-[280px]";

  const glassPanel = isDark
    ? "border-white/[0.09] bg-slate-900/65"
    : "border-slate-200/80 bg-white/75";

  const secondaryText = isDark
    ? "text-slate-400"
    : "text-slate-600";

  const headingText = isDark
    ? "text-white"
    : "text-slate-900";

  const controlStyle = isDark
    ? "border-white/10 bg-white/[0.05] text-slate-300 hover:bg-white/10"
    : "border-slate-200 bg-white/70 text-slate-700 hover:bg-white";

  return (
    <div
      data-theme={theme}
      className={`idps-theme relative min-h-screen overflow-x-hidden transition-colors duration-300 ${
        isDark
          ? "bg-[#070b16] text-white"
          : "bg-[#edf3fc] text-slate-900"
      }`}
    >
      {/* Ambient Background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div
          className={`absolute -left-40 -top-40 h-[500px] w-[500px] rounded-full blur-[130px] ${
            isDark ? "bg-blue-600/15" : "bg-blue-400/20"
          }`}
        />

        <div
          className={`absolute right-[-100px] top-[20%] h-[450px] w-[450px] rounded-full blur-[140px] ${
            isDark ? "bg-cyan-500/10" : "bg-cyan-300/25"
          }`}
        />

        <div
          className={`absolute bottom-[-150px] left-[35%] h-[400px] w-[400px] rounded-full blur-[140px] ${
            isDark ? "bg-indigo-600/10" : "bg-indigo-300/20"
          }`}
        />
      </div>

      {/* Mobile Overlay */}
      {mobileOpen && (
        <button
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm lg:hidden"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed inset-y-3 left-3 z-50 flex flex-col
          rounded-[28px] border
          shadow-[0_20px_80px_rgba(0,0,0,0.18)]
          backdrop-blur-2xl
          transition-all duration-300 ease-in-out
          ${glassPanel}
          ${collapsed ? "w-[76px]" : "w-[264px]"}
          ${mobileOpen ? "translate-x-0" : "-translate-x-[120%]"}
          lg:translate-x-0
        `}
      >
        {/* Logo */}
        <div
          className={`flex h-[82px] shrink-0 items-center justify-between border-b px-4 ${
            isDark ? "border-white/[0.07]" : "border-slate-200"
          }`}
        >
          <button
            onClick={() => navigate("/dashboard")}
            className="flex min-w-0 items-center gap-3"
            title="IDPS Shield home"
          >
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-cyan-400/20 bg-gradient-to-br from-cyan-400/20 to-blue-500/20 text-cyan-500 shadow-lg shadow-cyan-500/10">
              <ShieldCheck size={25} />
            </div>

            {!collapsed && (
              <div className="text-left">
                <h2 className={`text-[16px] font-bold tracking-wide ${headingText}`}>
                  IDPS Shield
                </h2>

                <p className={`mt-0.5 text-[10px] font-medium uppercase tracking-[2px] ${secondaryText}`}>
                  Cyber Defense
                </p>
              </div>
            )}
          </button>

          <button
            onClick={() => setMobileOpen(false)}
            className={`rounded-xl p-2 hover:bg-black/5 lg:hidden ${secondaryText}`}
            aria-label="Close sidebar"
          >
            <X size={19} />
          </button>
        </div>

        {/* Navigation */}
        <div className="flex-1 overflow-y-auto px-3 py-6">
          {!collapsed && (
            <p className={`mb-4 px-3 text-[10px] font-bold tracking-[2px] ${secondaryText}`}>
              SECURITY CENTER
            </p>
          )}

          <nav className="space-y-1.5">
            {navigation.map(({ label, path, icon: Icon }) => (
              <NavLink
                key={path}
                to={path}
                title={collapsed ? label : undefined}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) => `
                  group relative flex items-center gap-3 overflow-hidden
                  rounded-2xl border px-3.5 py-3
                  text-[13px] font-medium transition-all duration-200
                  ${
                    isActive
                      ? isDark
                        ? "border-cyan-300/15 bg-gradient-to-r from-cyan-400/15 to-blue-500/10 text-cyan-200 shadow-[inset_0_0_20px_rgba(34,211,238,0.04)]"
                        : "border-cyan-500/20 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 text-blue-700"
                      : isDark
                        ? "border-transparent text-slate-400 hover:border-white/[0.06] hover:bg-white/[0.06] hover:text-white"
                        : "border-transparent text-slate-600 hover:border-slate-200 hover:bg-slate-100/80 hover:text-slate-950"
                  }
                  ${collapsed ? "justify-center px-0" : ""}
                `}
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span className="absolute bottom-2 left-0 top-2 w-[3px] rounded-r-full bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.8)]" />
                    )}

                    <Icon
                      size={19}
                      strokeWidth={isActive ? 2.2 : 1.8}
                      className={`shrink-0 transition-transform duration-200 group-hover:scale-110 ${
                        isActive
                          ? isDark
                            ? "text-cyan-300"
                            : "text-blue-600"
                          : ""
                      }`}
                    />

                    {!collapsed && (
                      <span className="truncate">{label}</span>
                    )}

                    {isActive && !collapsed && (
                      <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.9)]" />
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </nav>
        </div>

        {/* User Profile - Fixed Collapsed Layout */}
        <div
          className={`shrink-0 border-t ${
            isDark ? "border-white/[0.07]" : "border-slate-200"
          } ${collapsed ? "p-2" : "p-3"}`}
        >
          {collapsed ? (
            /* Collapsed Profile */
            <div className="mb-3 flex justify-center">
              <button
                type="button"
                onClick={() => navigate("/profile")}
                title={`${user?.name ?? "User"}${user?.email ? ` · ${user.email}` : ""}`}
                aria-label="Open user profile"
                className="group flex h-12 w-12 shrink-0 items-center justify-center rounded-full border border-cyan-400/30 bg-gradient-to-br from-cyan-400/20 via-blue-500/15 to-indigo-500/20 text-cyan-500 shadow-[0_4px_18px_rgba(34,211,238,0.12)] transition-all duration-200 hover:scale-105 hover:border-cyan-400/60 hover:shadow-[0_4px_24px_rgba(34,211,238,0.25)] active:scale-95"
              >
                <UserRound
                  size={22}
                  strokeWidth={1.9}
                  className="transition-transform duration-200 group-hover:scale-110"
                />
              </button>
            </div>
          ) : (
            /* Expanded Profile */
            <button
              type="button"
              onClick={() => navigate("/profile")}
              title="View profile"
              className={`mb-3 flex w-full min-w-0 items-center gap-3 rounded-2xl border p-3 text-left transition-all hover:border-cyan-400/30 ${
                isDark
                  ? "border-white/[0.06] bg-white/[0.04] hover:bg-white/[0.07]"
                  : "border-slate-200 bg-white/70 hover:bg-white"
              }`}
            >
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-cyan-400/30 bg-gradient-to-br from-cyan-400/20 to-blue-500/20 text-cyan-600">
                <UserRound size={19} />
              </div>

              <div className="min-w-0 flex-1">
                <p className={`truncate text-sm font-semibold ${headingText}`}>
                  {user?.name ?? "User"}
                </p>

                <p className={`truncate text-[11px] ${secondaryText}`}>
                  {user?.email ?? ""}
                </p>
              </div>
            </button>
          )}

          {/* Sign Out */}
          <button
            onClick={handleLogout}
            title={collapsed ? "Sign Out" : undefined}
            aria-label="Sign out"
            className={`flex w-full items-center rounded-2xl text-[13px] font-medium text-red-400 transition-all hover:bg-red-500/10 hover:text-red-500 ${
              collapsed
                ? "justify-center px-0 py-3"
                : "gap-3 px-3.5 py-3"
            }`}
          >
            <LogOut size={19} />
            {!collapsed && "Sign Out"}
          </button>

          {/* Collapse Sidebar */}
          <button
            onClick={() => setCollapsed((value) => !value)}
            className={`mt-2 hidden w-full items-center justify-center rounded-xl border py-2.5 transition lg:flex ${controlStyle}`}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? (
              <ChevronRight size={18} />
            ) : (
              <ChevronLeft size={18} />
            )}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main
        className={`relative min-h-screen transition-all duration-300 ${sidebarWidth}`}
      >
        {/* Fixed Floating Glass Navbar */}
        <header
          className={`
            fixed top-3 right-3 left-3 z-40
            flex h-[72px] items-center justify-between
            rounded-[22px] border
            px-4 md:px-7
            backdrop-blur-2xl
            shadow-[0_8px_32px_rgba(0,0,0,0.10)]
            transition-all duration-300
            lg:left-[292px]
            ${collapsed ? "lg:!left-[104px]" : ""}
            ${
              isDark
                ? "border-white/[0.10] bg-slate-900/75"
                : "border-white/80 bg-white/75"
            }
          `}
        >
          {/* Page Title */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMobileOpen(true)}
              className={`rounded-xl border p-2.5 transition lg:hidden ${controlStyle}`}
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>

            <div>
              <h1 className={`text-lg font-semibold tracking-tight ${headingText}`}>
                {currentPage}
              </h1>

              <p className={`mt-0.5 hidden text-[11px] sm:block ${secondaryText}`}>
                Intelligent Cyber Defense System
              </p>
            </div>
          </div>

          {/* Navbar Actions */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* API Status */}
            <div
              className={`hidden items-center gap-2 rounded-full border px-4 py-2 sm:flex ${
                isDark
                  ? "border-emerald-400/15 bg-emerald-400/[0.07]"
                  : "border-emerald-500/20 bg-emerald-50"
              }`}
            >
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
              </span>

              <span className="text-[11px] font-medium text-emerald-500">
                API Monitoring
              </span>
            </div>

            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              aria-label={`Switch to ${isDark ? "light" : "dark"} mode`}
              title={`Switch to ${isDark ? "light" : "dark"} mode`}
              className={`flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-300 hover:scale-105 active:scale-95 ${controlStyle}`}
            >
              {isDark ? (
                <Sun size={19} className="text-amber-400" />
              ) : (
                <Moon size={19} className="text-indigo-600" />
              )}
            </button>

            {/* Notifications */}
            <button
              onClick={() => navigate("/alerts")}
              aria-label="View alerts"
              className={`relative flex h-10 w-10 items-center justify-center rounded-xl border transition hover:scale-105 ${controlStyle}`}
            >
              <Bell size={19} />
            </button>
          </div>
        </header>

        {/* Page Content */}
        <div className="relative min-h-screen px-4 pb-7 pt-[108px] md:px-7">
          <div className="mx-auto w-full max-w-[1800px]">
            <Outlet />
          </div>
        </div>

        {/* Footer */}
        <footer
          className={`relative border-t px-5 py-5 text-center text-[11px] ${
            isDark
              ? "border-white/[0.06] text-slate-500"
              : "border-slate-200 text-slate-500"
          }`}
        >
          <span className="text-cyan-500">IDPS Shield</span>
          {" "}· Intelligent Cyber Defense · Security analysis may be incomplete
        </footer>
      </main>
    </div>
  );
}
