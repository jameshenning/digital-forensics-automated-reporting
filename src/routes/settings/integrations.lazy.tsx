/**
 * /settings/integrations — lazy-loaded component bundle.
 *
 * Loaded on-demand when the user navigates to /settings/integrations.
 * The route definition and auth guard live in integrations.tsx; this file
 * provides the component via TanStack Router's createLazyFileRoute API.
 *
 * Sections:
 *   1. Agent Zero — URL, API key, port, allow_custom_url, test connection
 *   2. Network binding — read-only axum server status with amber warning for 0.0.0.0
 *   3. SMTP — host, port, username, password, from, TLS, test email
 *
 * SEC-4 §2.3: URL allowlist enforced by zod schema; amber banner when custom URL is active.
 * SEC-4 §2.14: network bind section shows amber warning for 0.0.0.0 binding.
 */

import React from "react";
import { createLazyFileRoute } from "@tanstack/react-router";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Bot,
  Brain,
  Mail,
  Network,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Eye,
  EyeOff,
  Upload,
  BarChart3,
  Check,
} from "lucide-react";

import {
  settingsGetAgentZero,
  settingsSetAgentZero,
  settingsTestAgentZero,
  settingsGetOllama,
  settingsSetOllama,
  settingsTestOllama,
  settingsGetSmtp,
  settingsSetSmtp,
  settingsTestSmtp,
  systemGetNetworkStatus,
  settingsGetUpload,
  settingsSetUpload,
  grafanaGetSettings,
} from "@/lib/bindings";
import { getToken, useSession } from "@/lib/session";
import { SettingsHeader } from "@/components/settings-header";
import { queryKeys } from "@/lib/query";
import { errorToMessage, toastError, toastSuccess } from "@/lib/error-toast";
import { agentZeroSchema, type AgentZeroFormValues } from "@/lib/agent-zero-schema";
import { smtpSchema, type SmtpFormValues } from "@/lib/smtp-schema";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";

// TanStack Router lazy route registration.
// The route ID must match the one in integrations.tsx exactly.
export const Route = createLazyFileRoute("/settings/integrations")({
  component: IntegrationsPage,
});

// ---------------------------------------------------------------------------
// Agent Zero section
// ---------------------------------------------------------------------------

function AgentZeroSection() {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [showApiKey, setShowApiKey] = React.useState(false);
  const [testResult, setTestResult] = React.useState<
    { ok: true; plugin_version?: string | null } | { ok: false; message: string } | null
  >(null);

  const { data: settings, isLoading } = useQuery({
    queryKey: queryKeys.agentZero.settings,
    queryFn: () => settingsGetAgentZero({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const form = useForm<AgentZeroFormValues>({
    resolver: zodResolver(agentZeroSchema),
    values: settings
      ? {
          url: settings.url ?? "http://localhost:5099",
          api_key: "",
          port: settings.port,
          allow_custom_url: settings.allow_custom_url,
          tor_enabled: settings.tor_enabled,
        }
      : undefined,
  });

  const saveMutation = useMutation({
    mutationFn: (values: AgentZeroFormValues) =>
      settingsSetAgentZero({
        token,
        input: {
          url: values.url,
          api_key: values.api_key && values.api_key.length > 0 ? values.api_key : null,
          port: values.port,
          allow_custom_url: values.allow_custom_url,
          tor_enabled: values.tor_enabled ?? false,
        },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.agentZero.settings });
      toastSuccess("Agent Zero settings saved.");
      form.setValue("api_key", "");
    },
    onError: (err) => {
      const code = (err as Partial<{ code: string }>)?.code;
      if (code === "AgentZeroUrlRejected") {
        form.setError("url", {
          message:
            "URL rejected: must be localhost, 127.0.0.1, or host.docker.internal. Enable 'Allow custom URL' to override.",
        });
      } else {
        toastError(err);
      }
    },
  });

  const testMutation = useMutation({
    mutationFn: () => settingsTestAgentZero({ token }),
    onSuccess: (result) => {
      setTestResult({ ok: true, plugin_version: result.plugin_version });
    },
    onError: (err) => {
      setTestResult({
        ok: false,
        message: errorToMessage(err, "Connection failed"),
      });
    },
  });

  const allowCustom = form.watch("allow_custom_url");

  // Status pill
  function StatusPill() {
    if (!settings) return null;
    if (!settings.is_configured)
      return <Badge variant="secondary">Not configured</Badge>;
    if (settings.allow_custom_url)
      return (
        <Badge className="bg-warning/20 text-warning border-warning/30">
          Custom URL active
        </Badge>
      );
    return (
      <Badge className="bg-success/20 text-success border-success/30">
        Configured
      </Badge>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Bot className="h-4 w-4" />
              Agent Zero
            </CardTitle>
            <CardDescription>
              Configure the Agent Zero AI integration for case summarization,
              enhancement, classification, and forensic analysis.
            </CardDescription>
          </div>
          {!isLoading && <StatusPill />}
        </div>
      </CardHeader>

      <CardContent>
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading settings...</p>
        ) : (
          <Form {...form}>
            <form
              onSubmit={form.handleSubmit((v) => saveMutation.mutate(v))}
              className="space-y-5"
              noValidate
            >
              {/* Allow custom URL warning */}
              {allowCustom && (
                <Alert className="border-warning/50 bg-warning/10">
                  <AlertTriangle className="h-4 w-4 text-warning" />
                  <AlertDescription className="text-warning">
                    <strong>Custom URL is active.</strong> DFARS will send case data
                    including investigator names, custody chains, and evidence descriptions
                    to a non-standard host. Verify this URL is trustworthy before
                    using any AI features.
                  </AlertDescription>
                </Alert>
              )}

              {/* URL */}
              <FormField
                control={form.control}
                name="url"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Agent Zero URL</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="http://localhost:5099"
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      Accepted: localhost, 127.0.0.1, host.docker.internal (any port).
                      Enable "Allow custom URL" to use a different host.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Port */}
              <FormField
                control={form.control}
                name="port"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Default port</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min={1}
                        max={65535}
                        {...field}
                        onChange={(e) => field.onChange(parseInt(e.target.value, 10) || 5099)}
                      />
                    </FormControl>
                    <FormDescription>
                      Default 5099 (Agent Zero's standard port).
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* API Key */}
              <div className="space-y-1.5">
                <Label htmlFor="az-api-key">API key</Label>
                {settings?.api_key_set && (
                  <p className="text-sm text-muted-foreground">
                    A key is already set (shown as{" "}
                    <code className="font-mono text-xs">••••••• (set)</code>).
                    Enter a new value to replace it, or leave blank to keep the existing key.
                  </p>
                )}
                <div className="relative">
                  <Input
                    id="az-api-key"
                    type={showApiKey ? "text" : "password"}
                    placeholder={settings?.api_key_set ? "Enter new key to replace" : "API key"}
                    autoComplete="off"
                    {...form.register("api_key")}
                  />
                  <button
                    type="button"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    onClick={() => setShowApiKey((p) => !p)}
                    aria-label={showApiKey ? "Hide API key" : "Show API key"}
                  >
                    {showApiKey ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Allow custom URL toggle */}
              <FormField
                control={form.control}
                name="allow_custom_url"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-start gap-3 space-y-0 rounded-md border p-4">
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                        aria-describedby="allow-custom-url-desc"
                      />
                    </FormControl>
                    <div className="space-y-1 leading-none">
                      <FormLabel>Allow custom URL (security override)</FormLabel>
                      <FormDescription id="allow-custom-url-desc">
                        Enables sending case data to a host outside the standard
                        allowlist (localhost / Docker). Only enable if your Agent Zero
                        is hosted on a trusted machine that you fully control.
                        An amber warning will appear whenever this is active.
                      </FormDescription>
                    </div>
                  </FormItem>
                )}
              />

              {/* Dark-web OSINT toggle — opt-in to Tor-routed dark-web tools
                  in the existing Run OSINT flow. Reuses the OSINT consent
                  gate; no new dialog. */}
              <FormField
                control={form.control}
                name="tor_enabled"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-start gap-3 space-y-0 rounded-md border border-purple-500/30 bg-purple-500/5 p-4">
                    <FormControl>
                      <Switch
                        checked={field.value ?? false}
                        onCheckedChange={field.onChange}
                        aria-describedby="tor-enabled-desc"
                      />
                    </FormControl>
                    <div className="space-y-1 leading-none">
                      <FormLabel>
                        Dark-web OSINT (via Tor)
                      </FormLabel>
                      <FormDescription id="tor-enabled-desc">
                        When enabled, each Run OSINT click additionally runs
                        SpiderFoot dark-web modules, onionsearch, and darkdump2
                        through a Tor circuit inside the Agent Zero container.
                        Results flow into the same Tools tab and forensic report
                        — no extra user steps.
                        <br />
                        <span className="font-medium text-warning">
                          Operational security:
                        </span>{" "}
                        your ISP and network-level monitoring can observe that
                        this machine uses Tor; exit-node operators see plaintext
                        clearnet probes that tools like SpiderFoot make;
                        non-reproducible circuit paths mean dark-web findings
                        should be treated as point-in-time snapshots in
                        forensic reports. Requires the Agent Zero container to
                        have <code>tor</code> + <code>torsocks</code> installed
                        and running — a preflight failure surfaces as
                        {" "}<em>Tor unavailable</em> in the error toast.
                      </FormDescription>
                    </div>
                  </FormItem>
                )}
              />

              {/* Actions */}
              <div className="flex gap-2 flex-wrap">
                <Button type="submit" disabled={saveMutation.isPending}>
                  {saveMutation.isPending ? "Saving..." : "Save settings"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  disabled={testMutation.isPending || !settings?.is_configured}
                  onClick={() => {
                    setTestResult(null);
                    testMutation.mutate();
                  }}
                >
                  {testMutation.isPending ? (
                    <RefreshCw className="h-4 w-4 mr-1.5 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-1.5" />
                  )}
                  Test connection
                </Button>
              </div>

              {/* Test result inline */}
              {testResult && (
                <div
                  className={`rounded-md border p-3 text-sm ${
                    testResult.ok
                      ? "border-success/40 bg-success/10 text-success"
                      : "border-destructive/40 bg-destructive/10 text-destructive"
                  }`}
                >
                  {testResult.ok ? (
                    <span className="flex items-center gap-1.5">
                      <CheckCircle2 className="h-4 w-4" />
                      Connected successfully
                      {testResult.plugin_version && (
                        <span className="text-xs ml-1 opacity-70">
                          (plugin v{testResult.plugin_version})
                        </span>
                      )}
                    </span>
                  ) : (
                    <span>Connection failed: {testResult.message}</span>
                  )}
                </div>
              )}
            </form>
          </Form>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Network binding section
// ---------------------------------------------------------------------------

function NetworkBindingSection() {
  const token = getToken() ?? "";

  const { data: netStatus, isLoading } = useQuery({
    queryKey: queryKeys.network.status,
    queryFn: () => systemGetNetworkStatus({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const isWideOpen = netStatus?.bind_host === "0.0.0.0";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4" />
          Network Binding
        </CardTitle>
        <CardDescription>
          Read-only status for the DFARS axum REST server (used by Agent Zero to
          push case data). Changing the bind host requires editing{" "}
          <code className="text-xs">%APPDATA%\DFARS\config.json</code> directly.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : netStatus ? (
          <>
            {/* Status row */}
            <div className="flex items-center gap-3">
              <div
                className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                  netStatus.axum_running ? "bg-success" : "bg-muted"
                }`}
              />
              <code className="text-sm font-mono">{netStatus.axum_url}</code>
              {isWideOpen ? (
                <Badge className="bg-warning/20 text-warning border-warning/30">
                  LOCAL NETWORK ACCESSIBLE
                </Badge>
              ) : (
                <Badge className="bg-success/20 text-success border-success/30">
                  Loopback only
                </Badge>
              )}
            </div>

            {/* Amber warning for 0.0.0.0 */}
            {isWideOpen && (
              <Alert className="border-warning/50 bg-warning/10">
                <AlertTriangle className="h-4 w-4 text-warning" />
                <AlertDescription className="text-warning">
                  <strong>Warning: bound to 0.0.0.0.</strong> The DFARS REST API
                  is reachable by any device on your local network, not just this
                  machine. Anyone on the same WiFi or LAN segment with a valid API
                  token can query or mutate chain-of-custody records. To restrict to
                  loopback only, edit{" "}
                  <code className="font-mono text-xs">config.json</code> and set{" "}
                  <code className="font-mono text-xs">bind_host = "127.0.0.1"</code>,
                  then restart DFARS.
                </AlertDescription>
              </Alert>
            )}

            <div className="text-xs text-muted-foreground space-y-1">
              <p>
                <strong>What is 0.0.0.0?</strong> Binding to 0.0.0.0 means the server
                listens on all network interfaces — Ethernet, WiFi, VPN, etc.
                Any device that can reach your machine at this IP can attempt
                requests to the API.
              </p>
              <p>
                The safety checkbox below does not change the bind address itself.
                It only records that you have acknowledged the network-wide exposure.
                To change the actual binding, edit the config file and restart.
              </p>
            </div>
          </>
        ) : (
          <p className="text-sm text-muted-foreground">
            Could not retrieve network status.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// SMTP section
// ---------------------------------------------------------------------------

function SmtpSection() {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [showPassword, setShowPassword] = React.useState(false);
  const [toAddress, setToAddress] = React.useState("");
  const [testResult, setTestResult] = React.useState<
    { ok: true } | { ok: false; message: string } | null
  >(null);

  const { data: settings, isLoading } = useQuery({
    queryKey: queryKeys.smtp.settings,
    queryFn: () => settingsGetSmtp({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const form = useForm<SmtpFormValues>({
    resolver: zodResolver(smtpSchema),
    values: settings
      ? {
          host: settings.host,
          port: settings.port,
          username: settings.username,
          password: "",
          from: settings.from,
          tls: settings.tls,
        }
      : undefined,
  });

  const saveMutation = useMutation({
    mutationFn: (values: SmtpFormValues) =>
      settingsSetSmtp({
        token,
        input: {
          host: values.host,
          port: values.port,
          username: values.username,
          password:
            values.password && values.password.length > 0
              ? values.password
              : null,
          from: values.from,
          tls: values.tls,
        },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.smtp.settings });
      toastSuccess("SMTP settings saved.");
      form.setValue("password", "");
    },
    onError: toastError,
  });

  const testMutation = useMutation({
    mutationFn: () => {
      if (!toAddress) throw new Error("Enter a 'to' address first.");
      return settingsTestSmtp({ token, to_address: toAddress });
    },
    onSuccess: () => {
      setTestResult({ ok: true });
    },
    onError: (err) => {
      setTestResult({
        ok: false,
        message: errorToMessage(err, "Send failed"),
      });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Mail className="h-4 w-4" />
          SMTP Email
        </CardTitle>
        <CardDescription>
          Configure outgoing email for case-share notifications and reports.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading settings...</p>
        ) : (
          <Form {...form}>
            <form
              onSubmit={form.handleSubmit((v) => saveMutation.mutate(v))}
              className="space-y-5"
              noValidate
            >
              {/* Host + Port row */}
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
                <div className="sm:col-span-3">
                  <FormField
                    control={form.control}
                    name="host"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>SMTP host</FormLabel>
                        <FormControl>
                          <Input placeholder="smtp.example.com" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                <FormField
                  control={form.control}
                  name="port"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Port</FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          min={1}
                          max={65535}
                          {...field}
                          onChange={(e) =>
                            field.onChange(parseInt(e.target.value, 10) || 587)
                          }
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Username */}
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="user@example.com"
                        autoComplete="username"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Password */}
              <div className="space-y-1.5">
                <Label htmlFor="smtp-password">Password</Label>
                {settings?.password_set && (
                  <p className="text-sm text-muted-foreground">
                    A password is already set. Leave blank to keep it, or enter a new value to replace it.
                  </p>
                )}
                <div className="relative">
                  <Input
                    id="smtp-password"
                    type={showPassword ? "text" : "password"}
                    placeholder={
                      settings?.password_set
                        ? "Enter new password to replace"
                        : "Password"
                    }
                    autoComplete="off"
                    {...form.register("password")}
                  />
                  <button
                    type="button"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    onClick={() => setShowPassword((p) => !p)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* From address */}
              <FormField
                control={form.control}
                name="from"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>From address</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="dfars@example.com"
                        type="email"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* TLS */}
              <FormField
                control={form.control}
                name="tls"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center gap-3 space-y-0">
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                    <FormLabel className="font-normal">Enable TLS / STARTTLS</FormLabel>
                  </FormItem>
                )}
              />

              <Button type="submit" disabled={saveMutation.isPending}>
                {saveMutation.isPending ? "Saving..." : "Save settings"}
              </Button>

              {/* Test email */}
              <div className="border-t pt-4 space-y-3">
                <p className="text-sm font-medium">Send test email</p>
                <div className="flex gap-2">
                  <Input
                    type="email"
                    placeholder="recipient@example.com"
                    value={toAddress}
                    onChange={(e) => {
                      setToAddress(e.target.value);
                      setTestResult(null);
                    }}
                    aria-label="Test email recipient"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    disabled={testMutation.isPending || !toAddress}
                    onClick={() => {
                      setTestResult(null);
                      testMutation.mutate();
                    }}
                  >
                    {testMutation.isPending ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      "Send test"
                    )}
                  </Button>
                </div>

                {testResult && (
                  <div
                    className={`rounded-md border p-3 text-sm ${
                      testResult.ok
                        ? "border-success/40 bg-success/10 text-success"
                        : "border-destructive/40 bg-destructive/10 text-destructive"
                    }`}
                  >
                    {testResult.ok ? (
                      <span className="flex items-center gap-1.5">
                        <CheckCircle2 className="h-4 w-4" />
                        Test email sent successfully.
                      </span>
                    ) : (
                      <span>Failed: {testResult.message}</span>
                    )}
                  </div>
                )}
              </div>
            </form>
          </Form>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Upload settings section
// ---------------------------------------------------------------------------

function UploadSettingsSection() {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [maxGiB, setMaxGiB] = React.useState<string>("");

  const { data: settings, isLoading } = useQuery({
    queryKey: queryKeys.upload.settings,
    queryFn: () => settingsGetUpload({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  React.useEffect(() => {
    if (settings) {
      setMaxGiB((settings.max_upload_bytes / (1024 * 1024 * 1024)).toString());
    }
  }, [settings]);

  const saveMutation = useMutation({
    mutationFn: () => {
      const gib = parseFloat(maxGiB);
      if (isNaN(gib) || gib < 1) {
        return Promise.reject(new Error("Must be at least 1 GiB"));
      }
      return settingsSetUpload({
        token,
        max_upload_bytes: Math.round(gib * 1024 * 1024 * 1024),
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.upload.settings });
      toastSuccess("Upload limit saved.");
    },
    onError: toastError,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Upload className="h-4 w-4" />
          Evidence File Uploads
        </CardTitle>
        <CardDescription>
          Configure the maximum size for evidence file uploads.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <div className="h-8 w-32 bg-muted rounded animate-pulse" />
        ) : settings ? (
          <>
            <div className="space-y-1.5">
              <Label htmlFor="max-upload-gib">Maximum upload size (GiB)</Label>
              <div className="flex gap-2">
                <Input
                  id="max-upload-gib"
                  type="number"
                  min={1}
                  step={1}
                  value={maxGiB}
                  onChange={(e) => setMaxGiB(e.target.value)}
                  className="w-32"
                />
                <Button
                  type="button"
                  onClick={() => saveMutation.mutate()}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? "Saving..." : "Save"}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Default: 50 GiB. Minimum: 1 GiB. Files larger than{" "}
                {Math.round(settings.large_file_warn_bytes / (1024 * 1024 * 1024))} GiB trigger a
                soft warning.
              </p>
            </div>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function GrafanaSection() {
  const token = getToken() ?? "";

  const { data: settings, isLoading } = useQuery({
    queryKey: queryKeys.grafana.settings,
    queryFn: () => grafanaGetSettings({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <BarChart3 className="h-4 w-4" />
          Grafana Dashboards
        </CardTitle>
        <CardDescription>
          Embedded Grafana dashboards for interactive entity network graphs
          and case statistics.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <div className="h-8 w-32 bg-muted rounded animate-pulse" />
        ) : settings ? (
          <>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span
                  className={`inline-flex h-2.5 w-2.5 rounded-full ${
                    settings.running ? "bg-success" : "bg-muted"
                  }`}
                />
                <span className="text-sm">
                  {settings.running
                    ? "Running"
                    : settings.enabled
                      ? "Ready to start"
                      : "Not configured"}
                </span>
              </div>
              {settings.enabled && (
                <span className="text-xs text-muted-foreground">
                  {settings.url}
                </span>
              )}
            </div>

            {!settings.docker_available && (
              <Alert className="border-warning/50 bg-warning/10">
                <AlertTriangle className="h-4 w-4 text-warning" />
                <AlertDescription className="text-warning">
                  <strong>Docker is not available.</strong> Install{" "}
                  <a
                    href="https://www.docker.com/products/docker-desktop"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline"
                  >
                    Docker Desktop
                  </a>{" "}
                  and ensure the engine is running. Grafana dashboards will
                  auto-start when you open the Grafana tab on any case.
                </AlertDescription>
              </Alert>
            )}

            <ul className="text-xs text-muted-foreground space-y-1">
              <li className="flex items-center gap-1.5">
                <Check className="h-3 w-3 text-success" />
                Auto-starts when you open the Grafana tab on any case
              </li>
              <li className="flex items-center gap-1.5">
                <Check className="h-3 w-3 text-success" />
                Generates a secure service token on first use
              </li>
              <li className="flex items-center gap-1.5">
                <Check className="h-3 w-3 text-success" />
                Network graphs, entity stats, and case timelines
              </li>
            </ul>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Ollama (Local LLM) section
// ---------------------------------------------------------------------------

function OllamaSection() {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [testResult, setTestResult] = React.useState<
    | { ok: true; model_loaded: boolean }
    | { ok: false; message: string }
    | null
  >(null);

  const { data: settings, isLoading } = useQuery({
    queryKey: queryKeys.ollama.settings,
    queryFn: () => settingsGetOllama({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const saveMutation = useMutation({
    mutationFn: (input: { url: string | null; model: string | null }) =>
      settingsSetOllama({ token, input }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.ollama.settings });
      toastSuccess("Ollama settings saved");
    },
    onError: toastError,
  });

  const testMutation = useMutation({
    mutationFn: () => settingsTestOllama({ token }),
    onSuccess: (result) => {
      setTestResult({ ok: true, model_loaded: result.model_loaded });
    },
    onError: (err) => {
      setTestResult({ ok: false, message: errorToMessage(err) });
    },
  });

  const [url, setUrl] = React.useState("");
  const [model, setModel] = React.useState("");

  React.useEffect(() => {
    if (settings) {
      setUrl(settings.url ?? "http://localhost:11434");
      setModel(settings.model ?? "mistral");
    }
  }, [settings]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Brain className="h-4 w-4" />
          Local LLM (Ollama)
        </CardTitle>
        <CardDescription>
          Free, local AI text enhancement. Runs entirely on your machine — no
          API keys, no data leaves the host.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <div className="h-20 bg-muted rounded animate-pulse" />
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="ollama-url">Ollama URL</Label>
                <Input
                  id="ollama-url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="http://localhost:11434"
                />
                <p className="text-xs text-muted-foreground">
                  Must point to localhost, 127.0.0.1, or host.docker.internal.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="ollama-model">Model</Label>
                <Input
                  id="ollama-model"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder="mistral"
                />
                <p className="text-xs text-muted-foreground">
                  Default: mistral. Also try llama3 or gemma.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Button
                type="button"
                onClick={() =>
                  saveMutation.mutate({
                    url: url || null,
                    model: model || null,
                  })
                }
                disabled={saveMutation.isPending}
              >
                {saveMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Save
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setTestResult(null);
                  testMutation.mutate();
                }}
                disabled={testMutation.isPending}
              >
                {testMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-4 w-4 mr-2" />
                )}
                Test Connection
              </Button>
            </div>

            {testResult && (
              <div>
                {testResult.ok ? (
                  <Alert className="border-success/50 bg-success/10">
                    <CheckCircle2 className="h-4 w-4 text-success" />
                    <AlertDescription className="text-success">
                      <strong>Ollama is reachable.</strong>{" "}
                      {testResult.model_loaded
                        ? "Model is loaded and ready."
                        : "Server is up, but the configured model is not yet pulled. Run: docker exec -it dfars-ollama ollama pull " +
                          (model || "mistral")}
                    </AlertDescription>
                  </Alert>
                ) : (
                  <Alert className="border-destructive/50 bg-destructive/10">
                    <AlertTriangle className="h-4 w-4 text-destructive" />
                    <AlertDescription className="text-destructive">
                      <strong>Connection failed.</strong>{" "}
                      {testResult.message}
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            )}

            <Alert className="border-primary/50 bg-primary/10">
              <AlertTriangle className="h-4 w-4 text-primary" />
              <AlertDescription className="text-primary">
                <strong>First-time setup:</strong>{" "}
                <code className="text-xs bg-background/60 px-1 rounded">
                  docker compose up -d ollama
                </code>{" "}
                then{" "}
                <code className="text-xs bg-background/60 px-1 rounded">
                  docker exec -it dfars-ollama ollama pull mistral
                </code>
                . The model download is ~4 GB.
              </AlertDescription>
            </Alert>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function IntegrationsPage() {
  const { session } = useSession();
  if (!session) return null;
  return (
    <div className="min-h-screen bg-background">
      <SettingsHeader username={session.username} />

      <main className="mx-auto max-w-3xl px-6 py-8 flex flex-col gap-6">
        <AgentZeroSection />
        <OllamaSection />
        <NetworkBindingSection />
        <SmtpSection />
        <UploadSettingsSection />
        <GrafanaSection />
      </main>
    </div>
  );
}
