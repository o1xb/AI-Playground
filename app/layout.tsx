import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI Playground",
  description: "Test AI Prompts",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="font-mono">
      <body>
        {children}
      </body>
    </html>
  );
}
