/**
 * AIEnhanceButton — reusable button for enhancing narrative text via local Ollama LLM.
 *
 * Usage:
 *   <AIEnhanceButton text={field.value} onResult={(t) => field.onChange(t)}>
 *     AI Enhance
 *   </AIEnhanceButton>
 *
 * Disabled when:
 *   - `text` is empty
 *   - The mutation is in-flight (shows a spinner)
 *
 * Error handling:
 *   - OllamaUnavailable → toast with Docker setup hint
 *   - All other errors → toastError()
 */

import React from "react";
import { useMutation, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Sparkles, Loader2 } from "lucide-react";

import { ollamaEnhance } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError } from "@/lib/error-toast";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";

// Local QueryClient so AIEnhanceButton works anywhere — even outside a
// QueryClientProvider (e.g. in unit tests or legacy form components).
const localQueryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface AIEnhanceButtonProps {
  text: string;
  onResult: (newText: string) => void;
  disabled?: boolean;
  children?: React.ReactNode;
}

// ---------------------------------------------------------------------------
// Inner component (uses useMutation — must be inside QueryClientProvider)
// ---------------------------------------------------------------------------

function AIEnhanceButtonInner({
  text,
  onResult,
  disabled = false,
  children = "AI Enhance",
}: AIEnhanceButtonProps) {
  const token = getToken();

  const enhanceMutation = useMutation({
    mutationFn: (t: string) => {
      if (!token) throw new Error("No session token");
      return ollamaEnhance({ token, text: t });
    },
    onSuccess: (result) => {
      onResult(result);
      toast.success("Enhanced", {
        description: "Your narrative has been expanded by the local AI.",
      });
    },
    onError: (err) => {
      const code = (err as Partial<{ code: string }>)?.code;
      if (code === "OllamaUnavailable") {
        toast.error("Ollama is not running", {
          description:
            "Start the local LLM with: docker compose up -d ollama",
        });
      } else if (code === "OllamaNotConfigured") {
        toast.error("Ollama not configured", {
          description:
            "Go to Settings → Integrations → Local LLM to configure Ollama.",
        });
      } else {
        toastError(err);
      }
    },
  });

  const isTextEmpty = text.trim().length === 0;
  const isDisabled = disabled || isTextEmpty || enhanceMutation.isPending;

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={() => enhanceMutation.mutate(text)}
      disabled={isDisabled}
      aria-label={
        isTextEmpty
          ? "Enter some text first to use AI Enhance"
          : "Enhance with AI"
      }
    >
      {enhanceMutation.isPending ? (
        <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
      ) : (
        <Sparkles className="h-3.5 w-3.5 mr-1.5" />
      )}
      {enhanceMutation.isPending ? "Enhancing…" : children}
    </Button>
  );
}

// ---------------------------------------------------------------------------
// Public wrapper (provides QueryClientProvider)
// ---------------------------------------------------------------------------

export function AIEnhanceButton(props: AIEnhanceButtonProps) {
  return (
    <QueryClientProvider client={localQueryClient}>
      <AIEnhanceButtonInner {...props} />
    </QueryClientProvider>
  );
}
