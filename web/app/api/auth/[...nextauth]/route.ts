/**
 * NextAuth.js route handler — GitHub OAuth + credentials providers.
 */

import NextAuth from "next-auth";
import type { NextAuthOptions } from "next-auth";
import GithubProvider from "next-auth/providers/github";
import CredentialsProvider from "next-auth/providers/credentials";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

export const authOptions: NextAuthOptions = {
  providers: [
    GithubProvider({
      clientId: process.env.GITHUB_CLIENT_ID || "",
      clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
    }),
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;

        try {
          const res = await fetch(`${API_URL}/v1/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email: credentials.email,
              password: credentials.password,
            }),
          });

          if (!res.ok) return null;

          const data = await res.json();
          return {
            id: data.access_token,
            email: credentials.email,
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
          };
        } catch {
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account }) {
      // Sync GitHub user with backend on sign-in
      if (account?.provider === "github" && account.access_token) {
        try {
          await fetch(`${API_URL}/v1/auth/github`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              github_id: Number(user.id),
              username: user.name || user.email?.split("@")[0] || "user",
              email: user.email,
              avatar_url: user.image,
              access_token: account.access_token,
            }),
          });
        } catch {
          // Don't block sign-in on backend sync failure
        }
      }
      return true;
    },
    async jwt({ token, user, account }) {
      if (account?.provider === "github" && account.access_token) {
        // Fetch ZASEON token from backend
        try {
          const res = await fetch(`${API_URL}/v1/auth/github`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              github_id: Number(user?.id || token.sub),
              username: user?.name || user?.email?.split("@")[0] || "user",
              email: user?.email,
              avatar_url: user?.image,
              access_token: account.access_token,
            }),
          });

          if (res.ok) {
            const data = await res.json();
            token.accessToken = data.access_token;
            token.refreshToken = data.refresh_token;
          }
        } catch {
          // Use GitHub token as fallback
        }
      }

      // Credentials flow — token stored directly
      if (user && "accessToken" in user) {
        token.accessToken = (user as any).accessToken;
        token.refreshToken = (user as any).refreshToken;
      }

      return token;
    },
    async session({ session, token }) {
      (session as any).accessToken = token.accessToken;
      return session;
    },
  },
  pages: {
    signIn: "/auth/signin",
  },
  session: {
    strategy: "jwt",
    maxAge: 60 * 60, // 1 hour
  },
  secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
