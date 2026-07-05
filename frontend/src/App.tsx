import { Link, Outlet, useLocation } from "react-router-dom";
import { ShieldCheck, Settings, FolderSearch } from "lucide-react";

export default function App() {
  const loc = useLocation();
  const onSettings = loc.pathname.startsWith("/settings");
  return (
    <div className="min-h-screen flex flex-col">
      <header className="sticky top-0 z-40 glass border-b border-white/5">
        <div className="max-w-[1600px] mx-auto px-6 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="grid place-items-center w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 group-hover:shadow-glow transition">
              <ShieldCheck size={18} className="text-accent-cyan" />
            </div>
            <div className="leading-tight">
              <div className="font-extrabold tracking-tight text-ink-50">
                Investigator
              </div>
              <div className="text-[10px] uppercase tracking-widest text-ink-400">
                DFIR · AI Forensics
              </div>
            </div>
          </Link>
          <nav className="flex items-center gap-1.5">
            <Link
              to="/"
              className={`btn-ghost ${!onSettings ? "text-accent-cyan" : ""}`}
            >
              <FolderSearch size={16} /> Cases
            </Link>
            <Link
              to="/settings"
              className={`btn-ghost ${onSettings ? "text-accent-cyan" : ""}`}
            >
              <Settings size={16} /> Settings
            </Link>
          </nav>
        </div>
      </header>
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
