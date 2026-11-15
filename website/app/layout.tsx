import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "auth-chaser — defensive auth verification",
  description:
    "Open-source tool that verifies authentication and authorization on applications you own or are authorized to test.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Syne:wght@600;700;800&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <div className="shell">
          <header className="site-header">
            <a className="brand" href="/">
              auth-<span>chaser</span>
            </a>
            <nav className="nav" aria-label="Primary">
              <a href="/docs/">Docs</a>
              <a href="/packs/">Packs</a>
              <a href="/download/">Download</a>
              <a href="https://github.com/Romstar/auth-chaser">GitHub</a>
            </nav>
          </header>
          {children}
          <footer className="site-footer">
            <div>Apache-2.0 · Defensive use only</div>
            <div>
              <a href="/docs/">How to use</a>
              {" · "}
              <a href="https://github.com/Romstar/auth-chaser">Source</a>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}
