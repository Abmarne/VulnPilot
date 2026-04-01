import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VulnPilot",
  description: "AI-assisted secure code review for GitHub repositories."
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
