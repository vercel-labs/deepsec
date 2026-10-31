import { Analytics } from "@vercel/analytics/next";
import { Footer } from "@vercel/geistdocs/footer";
import { Navbar } from "@vercel/geistdocs/navbar";
import { SpeedInsights } from "@vercel/speed-insights/next";
import type { Metadata } from "next";
import { GeistdocsProvider } from "@/components/geistdocs/provider";
import { config } from "@/lib/geistdocs/config";
import { mono, sans } from "@/lib/geistdocs/fonts";
import "./globals.css";

export const metadata: Metadata = {
  title: "deepsec - Full-repository security review",
  description:
    "deepsec is an open source vulnerability scanner that runs coding agents over entire repositories, in your own infrastructure, to find bugs that pull request review never revisits.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${sans.variable} ${mono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <body className="flex min-h-full flex-col">
        <GeistdocsProvider>
          <Navbar config={config} />
          {children}
          <Footer config={config} />
        </GeistdocsProvider>
        <Analytics />
        <SpeedInsights />
      </body>
    </html>
  );
}
