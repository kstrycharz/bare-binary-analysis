import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";
import { SidebarNav } from "@/components/sidebar-nav";

/* Self-hosted, not fetched from a CDN at runtime. next/font downloads the
   faces at build time and serves them from this app — which is the only
   acceptable arrangement for a product whose sidebar promises that artifacts
   never leave the network. A runtime request to a font host would both leak
   and, in an air-gapped deployment, simply fail. */
const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-plex-sans",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "BARE",
  description:
    "Shipped-artifact exposure scanner: secrets, sensitive data, and IP disclosure in the binaries you ship.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body className="min-h-screen font-sans antialiased">
        {/* Sidebar rather than a top bar: this console is a workbench, not a
            marketing site. Navigation stays put while a long findings table
            scrolls, and the viewport keeps its vertical space for data. */}
        <div className="flex min-h-screen">
          <SidebarNav />
          <div className="flex min-w-0 flex-1 flex-col">
            <main className="min-w-0 flex-1 px-6 py-7 lg:px-9">{children}</main>
            <footer className="border-t border-border px-6 py-3.5 text-[11px] text-content-subtle lg:px-9">
              Every finding is produced by a deterministic rule. AI assessments
              are labelled and can be hidden entirely.
            </footer>
          </div>
        </div>
      </body>
    </html>
  );
}
