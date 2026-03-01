import Link from "next/link";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Nav */}
      <nav className="border-b border-border px-6 py-4">
        <div className="mx-auto flex max-w-7xl items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-white font-bold text-sm">
              Z
            </div>
            <span className="text-xl font-bold">ZASEON</span>
          </div>
          <div className="flex items-center gap-6">
            <Link
              href="/quickscan"
              className="text-sm text-muted-foreground hover:text-foreground transition"
            >
              QuickScan
            </Link>
            <Link
              href="/dashboard"
              className="text-sm text-muted-foreground hover:text-foreground transition"
            >
              Dashboard
            </Link>
            <Link
              href="/dashboard"
              className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="mx-auto max-w-7xl px-6 py-24 text-center">
        <div className="mb-6 inline-flex items-center rounded-full border border-border px-4 py-1.5 text-sm text-muted-foreground">
          <span className="mr-2 inline-block h-2 w-2 rounded-full bg-safe animate-pulse" />
          AI-Powered Security with Zero False Positives
        </div>
        <h1 className="mx-auto max-w-4xl text-5xl font-extrabold leading-tight tracking-tight md:text-7xl">
          Audit Your Contracts.
          <br />
          <span className="bg-gradient-to-r from-primary to-purple-400 bg-clip-text text-transparent">
            Ship with Confidence.
          </span>
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg text-muted-foreground">
          ZASEON combines LLM-powered deep analysis, 700+ smart contract
          detectors, automated PoC verification, and Foundry-based exploit
          testing to find real vulnerabilities in your Solidity code — not
          noise.
        </p>
        <div className="mt-10 flex items-center justify-center gap-4">
          <Link
            href="/quickscan"
            className="rounded-xl bg-primary px-8 py-3 text-lg font-semibold text-primary-foreground hover:bg-primary/90 transition shadow-lg shadow-primary/25"
          >
            Try QuickScan — Free
          </Link>
          <Link
            href="/dashboard"
            className="rounded-xl border border-border px-8 py-3 text-lg font-semibold hover:bg-secondary transition"
          >
            View Dashboard
          </Link>
        </div>

        {/* Feature Grid */}
        <div className="mt-24 grid gap-6 md:grid-cols-3">
          {[
            {
              title: "Smart Contract Audit",
              desc: "700+ detectors covering 84 OWASP SCWE categories. Reentrancy, access control, oracle manipulation, and more.",
              icon: "⛓",
            },
            {
              title: "AI Deep Analysis",
              desc: "Multi-pass LLM analysis with taint tracking, business logic detection, and zero false positive targeting.",
              icon: "🧠",
            },
            {
              title: "PoC Verification",
              desc: "Automated proof-of-concept generation and sandboxed execution. Every finding is verified before reporting.",
              icon: "🔬",
            },
            {
              title: "Multi-Chain Support",
              desc: "Scan contracts on Ethereum, Polygon, BSC, Arbitrum, Optimism, Base, zkSync, Avalanche, and more EVM chains.",
              icon: "🌐",
            },
            {
              title: "GitHub Integration",
              desc: "Webhook-driven CI/CD scanning. Get findings as PR comments and block merges on critical issues.",
              icon: "🔗",
            },
            {
              title: "Professional Reports",
              desc: "PDF audit reports with security scores, SARIF for GitHub Security, and publishable public reports.",
              icon: "📊",
            },
          ].map((feature) => (
            <div
              key={feature.title}
              className="rounded-xl border border-border bg-card p-6 text-left hover:border-primary/50 transition"
            >
              <div className="mb-3 text-3xl">{feature.icon}</div>
              <h3 className="mb-2 text-lg font-semibold">{feature.title}</h3>
              <p className="text-sm text-muted-foreground">{feature.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Chains */}
      <section className="border-t border-border py-16">
        <div className="mx-auto max-w-7xl px-6 text-center">
          <p className="mb-8 text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Supported Chains
          </p>
          <div className="flex flex-wrap items-center justify-center gap-8 text-2xl text-muted-foreground">
            {[
              "Ethereum",
              "Polygon",
              "Arbitrum",
              "Optimism",
              "Base",
              "BSC",
              "Avalanche",
              "zkSync",
              "Linea",
              "Scroll",
            ].map((chain) => (
              <span key={chain} className="text-sm font-medium">
                {chain}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-8">
        <div className="mx-auto max-w-7xl px-6 text-center text-sm text-muted-foreground">
          © 2024 ZASEON. AI-Powered Smart Contract Security Scanner.
        </div>
      </footer>
    </div>
  );
}
