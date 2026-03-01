import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: string): string {
  const colors: Record<string, string> = {
    CRITICAL: "text-red-500",
    HIGH: "text-orange-500",
    MEDIUM: "text-yellow-500",
    LOW: "text-blue-500",
    INFO: "text-gray-400",
    GAS: "text-purple-400",
  };
  return colors[severity] || "text-gray-400";
}

export function severityBg(severity: string): string {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500/10 text-red-500 border-red-500/20",
    HIGH: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    MEDIUM: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    LOW: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    INFO: "bg-gray-500/10 text-gray-400 border-gray-500/20",
    GAS: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  };
  return colors[severity] || "bg-gray-500/10 text-gray-400";
}

export function scoreGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function scoreColor(score: number): string {
  if (score >= 90) return "text-green-500";
  if (score >= 80) return "text-lime-500";
  if (score >= 70) return "text-yellow-500";
  if (score >= 60) return "text-orange-500";
  return "text-red-500";
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

export function truncateAddress(address: string): string {
  if (address.length <= 10) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export const CHAINS: Record<
  string,
  { name: string; icon: string; explorer: string }
> = {
  ethereum: { name: "Ethereum", icon: "⟠", explorer: "https://etherscan.io" },
  polygon: { name: "Polygon", icon: "⬡", explorer: "https://polygonscan.com" },
  bsc: { name: "BNB Chain", icon: "◆", explorer: "https://bscscan.com" },
  avalanche: { name: "Avalanche", icon: "▲", explorer: "https://snowtrace.io" },
  arbitrum: { name: "Arbitrum", icon: "◈", explorer: "https://arbiscan.io" },
  optimism: {
    name: "Optimism",
    icon: "○",
    explorer: "https://optimistic.etherscan.io",
  },
  base: { name: "Base", icon: "◉", explorer: "https://basescan.org" },
  zksync: {
    name: "zkSync Era",
    icon: "◇",
    explorer: "https://explorer.zksync.io",
  },
  linea: { name: "Linea", icon: "━", explorer: "https://lineascan.build" },
  fantom: { name: "Fantom", icon: "◎", explorer: "https://ftmscan.com" },
  gnosis: { name: "Gnosis", icon: "◐", explorer: "https://gnosisscan.io" },
  scroll: { name: "Scroll", icon: "◑", explorer: "https://scrollscan.com" },
};
