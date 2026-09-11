"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

/* Icons are drawn, not imported: an icon font or SVG sprite is another asset
   to ship to an air-gapped deployment, and these five are all the console
   needs. Stroke-based on a 20px grid so they scale and recolour with the
   text beside them. */
function Icon({ path, filled }: { path: ReactNode; filled?: boolean }) {
  return (
    <svg
      viewBox="0 0 20 20"
      className="h-[17px] w-[17px] shrink-0"
      fill="none"
      stroke="currentColor"
      strokeWidth={filled ? 1.9 : 1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {path}
    </svg>
  );
}

const NAV = [
  {
    href: "/",
    label: "Runs",
    exact: true,
    icon: (
      <>
        <path d="M3 5.5h14M3 10h14M3 14.5h9" />
      </>
    ),
  },
  {
    href: "/scan",
    label: "New scan",
    icon: (
      <>
        <path d="M10 4v12M4 10h12" />
      </>
    ),
  },
  {
    href: "/rules",
    label: "Detections",
    icon: (
      <>
        <path d="M10 2.5 16.5 6v5c0 3.4-2.7 6-6.5 6.8C6.2 17 3.5 14.4 3.5 11V6Z" />
      </>
    ),
  },
  {
    href: "/settings",
    label: "Settings",
    icon: (
      <>
        <circle cx="10" cy="10" r="2.6" />
        <path d="M10 2.5v2M10 15.5v2M17.5 10h-2M4.5 10h-2M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4M15.3 15.3l-1.4-1.4M6.1 6.1 4.7 4.7" />
      </>
    ),
  },
];

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 hidden h-screen w-[228px] shrink-0 flex-col border-r border-border bg-surface shadow-[1px_0_0_0_oklch(0_0_0/0.25)] md:flex">
      <div className="border-b border-border px-5 py-[18px]">
        <Link href="/" className="block">
          <div className="flex items-center gap-2.5">
            {/* A lens: the product is about looking at what you ship. */}
            <svg viewBox="0 0 20 20" className="h-[21px] w-[21px] text-accent" aria-hidden>
              <circle cx="9" cy="9" r="6" fill="none" stroke="currentColor" strokeWidth="1.6" />
              <circle cx="9" cy="9" r="2.2" fill="currentColor" opacity="0.35" />
              <path
                d="M13.5 13.5 L18 18"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
              />
            </svg>
            <span className="text-[15px] font-semibold tracking-[-0.012em]">BARE</span>
          </div>
          <p className="mt-1.5 text-[11px] leading-tight text-content-subtle">
            Shipped-artifact exposure scanner
          </p>
        </Link>
      </div>

      <nav className="flex-1 px-2.5 py-3">
        <ul className="space-y-0.5">
          {NAV.map((item) => {
            const active = item.exact
              ? pathname === item.href
              : pathname.startsWith(item.href);
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={`group relative flex items-center gap-2.5 rounded-md px-3 py-[7px] text-[13px] transition-colors ${
                    active
                      ? "bg-surface-sunken font-medium text-content"
                      : "text-content-muted hover:bg-surface-sunken/70 hover:text-content"
                  }`}
                >
                  {/* The active marker is a rule, not a fill: it reads at a
                      glance without turning the rail into a block of colour. */}
                  <span
                    aria-hidden
                    className={`absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-full transition-colors ${
                      active ? "bg-accent" : "bg-transparent"
                    }`}
                  />
                  <span className={active ? "text-accent" : "text-content-subtle"}>
                    <Icon path={item.icon} filled={active} />
                  </span>
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="border-t border-border px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="h-[6px] w-[6px] rounded-full bg-ok" aria-hidden />
          <span className="text-[11px] font-medium text-content-muted">Self-hosted</span>
        </div>
        <p className="mt-1.5 text-[11px] leading-relaxed text-content-subtle">
          Artifacts never leave this network.
        </p>
      </div>
    </aside>
  );
}
