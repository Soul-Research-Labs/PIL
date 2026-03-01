"use client";

import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { cn } from "@/lib/utils";
import {
  Search,
  Send,
  ThumbsUp,
  ThumbsDown,
  Loader2,
  Sparkles,
  MessageSquare,
  HelpCircle,
} from "lucide-react";
import {
  nlQuery,
  nlQueryFollowup,
  nlQueryFeedback,
  getNLQueryExamples,
} from "@/lib/api";
import type { NLQueryResult, NLQueryExample, StructuredQuery } from "@/types";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  result?: NLQueryResult;
  feedbackGiven?: boolean;
}

export default function AskPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const lastStructuredQuery = useRef<StructuredQuery | undefined>(undefined);

  // ── Examples ──────────────────────────────────────────────────────────────

  const { data: examples = [] } = useQuery<NLQueryExample[]>({
    queryKey: ["nl-query-examples"],
    queryFn: getNLQueryExamples,
  });

  // ── Query mutation ────────────────────────────────────────────────────────

  const queryMut = useMutation({
    mutationFn: async (q: string) => {
      const isFollowup = messages.some((m) => m.role === "assistant");
      if (isFollowup && lastStructuredQuery.current) {
        return nlQueryFollowup(q, lastStructuredQuery.current);
      }
      return nlQuery(q);
    },
    onSuccess: (result, q) => {
      lastStructuredQuery.current = result.structured_query;
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          text: result.summary || "Here are your results.",
          result,
        },
      ]);
    },
  });

  const feedbackMut = useMutation({
    mutationFn: ({
      query,
      wasCorrect,
    }: {
      query: string;
      wasCorrect: boolean;
    }) => nlQueryFeedback(query, wasCorrect),
  });

  // ── Helpers ───────────────────────────────────────────────────────────────

  function handleSubmit(text?: string) {
    const q = (text || input).trim();
    if (!q || queryMut.isPending) return;

    setMessages((prev) => [
      ...prev,
      { id: crypto.randomUUID(), role: "user", text: q },
    ]);
    setInput("");
    queryMut.mutate(q);
  }

  function handleFeedback(msgId: string, wasCorrect: boolean) {
    setMessages((prev) =>
      prev.map((m) => (m.id === msgId ? { ...m, feedbackGiven: true } : m)),
    );
    const msg = messages.find((m) => m.id === msgId);
    if (msg?.result) {
      feedbackMut.mutate({
        query: msg.result.original_query || "",
        wasCorrect,
      });
    }
  }

  // ── Auto scroll ───────────────────────────────────────────────────────────

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, queryMut.isPending]);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)]">
      <Header title="Ask" />

      {/* Chat body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4 max-w-3xl mx-auto w-full">
        {messages.length === 0 && (
          <EmptyState examples={examples} onSelect={(q) => handleSubmit(q)} />
        )}

        {messages.map((msg) => (
          <div key={msg.id}>
            {msg.role === "user" ? (
              <div className="flex justify-end">
                <div className="rounded-lg bg-primary text-primary-foreground px-4 py-2 max-w-[80%] text-sm">
                  {msg.text}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex gap-2">
                  <Sparkles className="h-5 w-5 text-primary mt-0.5 shrink-0" />
                  <div className="rounded-lg border bg-card px-4 py-3 max-w-[90%] text-sm space-y-3">
                    <p>{msg.text}</p>

                    {/* Results table */}
                    {msg.result?.data && msg.result.data.length > 0 && (
                      <div className="rounded border overflow-hidden">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="bg-muted/40 border-b">
                              {Object.keys(msg.result.data[0]).map((k) => (
                                <th
                                  key={k}
                                  className="p-2 text-left font-medium text-muted-foreground"
                                >
                                  {k}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {msg.result.data
                              .slice(0, 20)
                              .map(
                                (row: Record<string, unknown>, i: number) => (
                                  <tr
                                    key={i}
                                    className="border-b last:border-0 hover:bg-muted/20"
                                  >
                                    {Object.values(row).map((v, j) => (
                                      <td key={j} className="p-2">
                                        {String(v ?? "—")}
                                      </td>
                                    ))}
                                  </tr>
                                ),
                              )}
                          </tbody>
                        </table>
                        {msg.result.data.length > 20 && (
                          <div className="text-xs text-muted-foreground p-2 text-center">
                            Showing 20 of {msg.result.data.length} results
                          </div>
                        )}
                      </div>
                    )}

                    {msg.result?.total_count !== undefined && (
                      <p className="text-xs text-muted-foreground">
                        Total results: {msg.result.total_count}
                      </p>
                    )}

                    {/* Feedback */}
                    {!msg.feedbackGiven && (
                      <div className="flex items-center gap-2 pt-1">
                        <span className="text-xs text-muted-foreground">
                          Was this helpful?
                        </span>
                        <button
                          onClick={() => handleFeedback(msg.id, true)}
                          className="text-muted-foreground hover:text-green-500 transition"
                        >
                          <ThumbsUp className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => handleFeedback(msg.id, false)}
                          className="text-muted-foreground hover:text-red-500 transition"
                        >
                          <ThumbsDown className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    )}
                    {msg.feedbackGiven && (
                      <p className="text-xs text-muted-foreground">
                        Thanks for the feedback!
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}

        {queryMut.isPending && (
          <div className="flex gap-2">
            <Sparkles className="h-5 w-5 text-primary mt-0.5 shrink-0 animate-pulse" />
            <div className="rounded-lg border bg-card px-4 py-3 text-sm text-muted-foreground flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" /> Thinking…
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Input area */}
      <div className="border-t bg-background p-4">
        <div className="max-w-3xl mx-auto flex gap-2">
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSubmit();
              }
            }}
            placeholder="Ask about your findings, scans, or contracts…"
            className="flex-1 rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            disabled={queryMut.isPending}
          />
          <button
            onClick={() => handleSubmit()}
            disabled={!input.trim() || queryMut.isPending}
            className="rounded-md bg-primary px-4 py-2 text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Empty state with examples ───────────────────────────────────────────────

function EmptyState({
  examples,
  onSelect,
}: {
  examples: NLQueryExample[];
  onSelect: (query: string) => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center h-full space-y-6 py-16">
      <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center">
        <MessageSquare className="h-8 w-8 text-primary" />
      </div>
      <div className="text-center space-y-2">
        <h2 className="text-xl font-semibold">Ask anything</h2>
        <p className="text-muted-foreground text-sm max-w-md">
          Query your security data in plain English. Ask about findings,
          contracts, severity trends, and more.
        </p>
      </div>

      {examples.length > 0 && (
        <div className="grid gap-2 w-full max-w-lg">
          <p className="text-xs text-muted-foreground font-medium flex items-center gap-1">
            <HelpCircle className="h-3 w-3" /> Try these examples
          </p>
          {examples.map((ex, i) => (
            <button
              key={i}
              onClick={() => onSelect(ex.query)}
              className="rounded-lg border bg-card p-3 text-left hover:bg-muted/40 transition text-sm"
            >
              <div className="font-medium">{ex.query}</div>
              {ex.description && (
                <div className="text-xs text-muted-foreground mt-0.5">
                  {ex.description}
                </div>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
