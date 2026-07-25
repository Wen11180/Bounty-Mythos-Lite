import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "赏金神话·轻量版",
  description: "漏洞赏金研究助手基础设施",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
