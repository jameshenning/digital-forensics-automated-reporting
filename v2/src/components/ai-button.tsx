/**
 * AIButton — reusable AI action button for case/evidence forms.
 *
 * Usage:
 *   <AIButton action="enhance" text={field.value} onResult={(t) => field.onChange(t)}>
 *     Polish with AI
 *   </AIButton>
 *
 * Disabled when:
 *   - `text` is empty
 *   - Agent Zero is not configured (shows a tooltip explaining why)
 *   - The mutation is in-flight (shows a spinner)
 *
 * Error handling:
 *   - AgentZeroNotConfigured → tooltip, no toast
 *   - All other errors → toastError()
 */

import React from "react";
import { useMutation } from "@tanstack/react-query";
import { Sparkles, Loader2 } from "lucide-react";

import { aiEnhance, aiClassify, type AiClassificationResult } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError } from "@/lib/error-toast";

import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface AIButtonEnhanceProps {
  action: "enhance";
  text: string;
  onResult: (newText: string) => void;
  children?: React.ReactNode;
  disabled?: boolean;
  /** True when the Agent Zero settings show is_configured = false */
  agentZeroConfigured?: boolean;
}

interface AIButtonClassifyProps {
  action: "classify";
  text: string;
  onResult: (result: AiClassificationResult) => void;
  children?: React.ReactNode;
  disabled?: boolean;
  /** True when the Agent Zero settings show is_configured = false */
  agentZeroConfigured?: boolean;
}

type AIButtonProps = AIButtonEnhanceProps | AIButtonClassifyProps;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AIButton({
  action,
  text,
  onResult,
  children = "AI",
  disabled = false,
  agentZeroConfigured = true,
}: AIButtonProps) {
  const token = getToken();

  const enhanceMutation = useMutation({
    mutationFn: (t: string) => {
      if (!token) throw new Error("No session token");
      return aiEnhance({ token, text: t });
    },
    onSuccess: (result) => {
      if (action === "enhance") {
        (onResult as (v: string) => void)(result);
      }
    },
    onError: (err) => {
      // AgentZeroNotConfigured is visible in the tooltip — don't double-toast
      const code = (err as Partial<{ code: string }>)?.code;
      if (code !== "AgentZeroNotConfigured") {
        toastError(err);
      }
    },
  });

  const classifyMutation = useMutation({
    mutationFn: (t: string) => {
      if (!token) throw new Error("No session token");
      return aiClassify({ token, text: t });
    },
    onSuccess: (result) => {
      if (action === "classify") {
        (onResult as (v: AiClassificationResult) => void)(result);
      }
    },
    onError: (err) => {
      const code = (err as Partial<{ code: string }>)?.code;
      if (code !== "AgentZeroNotConfigured") {
        toastError(err);
      }
    },
  });

  const isPending =
    action === "enhance" ? enhanceMutation.isPending : classifyMutation.isPending;

  const isTextEmpty = text.trim().length === 0;
  const isDisabled = disabled || isTextEmpty || !agentZeroConfigured || isPending;

  const handleClick = () => {
    if (action === "enhance") {
      enhanceMutation.mutate(text);
    } else {
      classifyMutation.mutate(text);
    }
  };

  const button = (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={handleClick}
      disabled={isDisabled}
      aria-label={
        !agentZeroConfigured
          ? "Configure Agent Zero in Settings to enable AI"
          : isTextEmpty
            ? "Enter some text first to use AI"
            : `${action === "enhance" ? "Enhance" : "Classify"} with AI`
      }
    >
      {isPending ? (
        <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
      ) : (
        <Sparkles className="h-3.5 w-3.5 mr-1.5" />
      )}
      {isPending ? "Working..." : children}
    </Button>
  );

  // Show tooltip when Agent Zero is not configured
  if (!agentZeroConfigured) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            {/* Wrap in span so tooltip fires on disabled button */}
            <span tabIndex={0} className="inline-flex">
              {button}
            </span>
          </TooltipTrigger>
          <TooltipContent>
            Configure Agent Zero in Settings to enable AI features
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return button;
}
