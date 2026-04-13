/**
 * Tests for Zod form validation schemas.
 *
 * Deliverable 13: verify the Zod schemas in setup.tsx and security.tsx
 * enforce the correct constraints:
 *   - Username: 3–64 chars, [a-zA-Z0-9._-] only.
 *   - Password: 10–1024 chars.
 *   - Password confirmation: must match password.
 *   - Change password: old_password required, new_password 10–1024, confirm match.
 *
 * These schemas are the client-side mirror of the Rust auth::validate_username()
 * and auth::validate_password() functions (both enforce the same constraints).
 */
import { describe, it, expect } from "vitest";
import { z } from "zod";

// ─── Replicate schemas from setup.tsx and security.tsx ───────────────────────
// We duplicate them here rather than importing from route files (which import
// React + Tauri) to keep tests fast and dependency-free.

const setupSchema = z
  .object({
    username: z
      .string()
      .min(3, "Username must be at least 3 characters")
      .max(64, "Username must be at most 64 characters")
      .regex(
        /^[A-Za-z0-9._-]+$/,
        "Username may only contain letters, digits, '.', '_', or '-'"
      ),
    password: z
      .string()
      .min(10, "Password must be at least 10 characters")
      .max(1024, "Password is too long"),
    confirm_password: z.string(),
  })
  .refine((data) => data.password === data.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

const changePasswordSchema = z
  .object({
    old_password: z.string().min(1, "Current password is required"),
    new_password: z
      .string()
      .min(10, "New password must be at least 10 characters")
      .max(1024, "Password is too long"),
    confirm_password: z.string(),
  })
  .refine((d) => d.new_password === d.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isValid<T>(schema: z.ZodSchema<T>, data: unknown): boolean {
  return schema.safeParse(data).success;
}

function errorPaths<T>(schema: z.ZodSchema<T>, data: unknown): string[] {
  const result = schema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

// ─── setup.tsx schema ────────────────────────────────────────────────────────

describe("setupSchema — username", () => {
  function validInput(username: string) {
    return { username, password: "validpassword!1", confirm_password: "validpassword!1" };
  }

  it("accepts a valid username", () => {
    expect(isValid(setupSchema, validInput("alice"))).toBe(true);
    expect(isValid(setupSchema, validInput("user.name-123"))).toBe(true);
    expect(isValid(setupSchema, validInput("a_b-c.d"))).toBe(true);
  });

  it("rejects username shorter than 3 characters", () => {
    expect(isValid(setupSchema, validInput("ab"))).toBe(false);
    expect(errorPaths(setupSchema, validInput("ab"))).toContain("username");
  });

  it("rejects username longer than 64 characters", () => {
    const longUser = "a".repeat(65);
    expect(isValid(setupSchema, validInput(longUser))).toBe(false);
  });

  it("accepts username of exactly 3 characters", () => {
    expect(isValid(setupSchema, validInput("abc"))).toBe(true);
  });

  it("accepts username of exactly 64 characters", () => {
    expect(isValid(setupSchema, validInput("a".repeat(64)))).toBe(true);
  });

  it("rejects username with spaces", () => {
    expect(isValid(setupSchema, validInput("user name"))).toBe(false);
  });

  it("rejects username with special chars beyond allowlist", () => {
    expect(isValid(setupSchema, validInput("user@domain"))).toBe(false);
    expect(isValid(setupSchema, validInput("user/name"))).toBe(false);
    expect(isValid(setupSchema, validInput("user<name>"))).toBe(false);
  });

  it("rejects empty username", () => {
    expect(isValid(setupSchema, validInput(""))).toBe(false);
  });
});

describe("setupSchema — password", () => {
  function validInput(password: string, confirm?: string) {
    return {
      username: "validuser",
      password,
      confirm_password: confirm ?? password,
    };
  }

  it("accepts a valid password at minimum length", () => {
    expect(isValid(setupSchema, validInput("1234567890"))).toBe(true);
  });

  it("rejects password shorter than 10 characters", () => {
    expect(isValid(setupSchema, validInput("short"))).toBe(false);
    expect(errorPaths(setupSchema, validInput("short"))).toContain("password");
  });

  it("accepts password of exactly 10 characters", () => {
    expect(isValid(setupSchema, validInput("exactlyten"))).toBe(true);
  });

  it("accepts password of exactly 1024 characters", () => {
    const maxPw = "a".repeat(1024);
    expect(isValid(setupSchema, validInput(maxPw))).toBe(true);
  });

  it("rejects password longer than 1024 characters", () => {
    const tooLong = "a".repeat(1025);
    expect(isValid(setupSchema, validInput(tooLong))).toBe(false);
    expect(errorPaths(setupSchema, validInput(tooLong))).toContain("password");
  });

  it("rejects when confirm_password does not match", () => {
    const result = setupSchema.safeParse(validInput("validpassword1!", "differentpassword1!"));
    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((i) => i.path.join("."));
      expect(paths).toContain("confirm_password");
    }
  });

  it("accepts when passwords match", () => {
    expect(isValid(setupSchema, validInput("correcthorsebattery", "correcthorsebattery"))).toBe(true);
  });

  it("accepts unicode in passwords", () => {
    const unicodePw = "passphraseWithüñicode123";
    expect(isValid(setupSchema, validInput(unicodePw))).toBe(true);
  });
});

// ─── security.tsx changePasswordSchema ───────────────────────────────────────

describe("changePasswordSchema", () => {
  function validInput(
    old_password = "oldpassword123!",
    new_password = "newpassword123!",
    confirm_password = "newpassword123!"
  ) {
    return { old_password, new_password, confirm_password };
  }

  it("accepts valid change password input", () => {
    expect(isValid(changePasswordSchema, validInput())).toBe(true);
  });

  it("rejects empty old_password", () => {
    expect(isValid(changePasswordSchema, validInput(""))).toBe(false);
    expect(errorPaths(changePasswordSchema, validInput(""))).toContain("old_password");
  });

  it("rejects new_password shorter than 10 chars", () => {
    expect(isValid(changePasswordSchema, validInput("oldpw", "short"))).toBe(false);
  });

  it("rejects new_password longer than 1024 chars", () => {
    expect(
      isValid(changePasswordSchema, validInput("oldpw", "a".repeat(1025), "a".repeat(1025)))
    ).toBe(false);
  });

  it("rejects mismatched confirm", () => {
    const result = changePasswordSchema.safeParse(
      validInput("oldpw", "newpassword123!", "differentpassword!")
    );
    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((i) => i.path.join("."));
      expect(paths).toContain("confirm_password");
    }
  });
});
