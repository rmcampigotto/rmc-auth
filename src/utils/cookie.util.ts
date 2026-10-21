export interface CookieSettings {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "strict" | "lax" | "none";
  path: string;
  domain?: string;
  /** Lifetime in seconds. */
  maxAgeSeconds?: number;
}

function base(settings: CookieSettings): Record<string, unknown> {
  const options: Record<string, unknown> = {
    httpOnly: settings.httpOnly,
    secure: settings.secure,
    sameSite: settings.sameSite,
    path: settings.path,
  };
  if (settings.domain) options.domain = settings.domain;
  return options;
}

/** Sets a cookie on an Express response (`res.cookie`) or a Fastify reply (`reply.setCookie`, @fastify/cookie). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function setResponseCookie(response: any, name: string, value: string, settings: CookieSettings): void {
  const options = base(settings);
  if (typeof response?.setCookie === "function") {
    // Fastify: maxAge in seconds.
    if (settings.maxAgeSeconds) options.maxAge = settings.maxAgeSeconds;
    response.setCookie(name, value, options);
    return;
  }
  if (typeof response?.cookie === "function") {
    // Express: maxAge in milliseconds.
    if (settings.maxAgeSeconds) options.maxAge = settings.maxAgeSeconds * 1000;
    response.cookie(name, value, options);
    return;
  }
  throw new Error("rmc-auth: the response does not support cookies (Express res.cookie or Fastify reply.setCookie with @fastify/cookie).");
}

/** Clears a cookie set by `setResponseCookie` (path and domain must match). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function clearResponseCookie(response: any, name: string, settings: CookieSettings): void {
  if (typeof response?.clearCookie !== "function") {
    throw new Error("rmc-auth: the response does not support cookies (Express res.clearCookie or Fastify reply.clearCookie).");
  }
  response.clearCookie(name, base(settings));
}

/** Reads a cookie from a request parsed by `cookie-parser` (Express) or `@fastify/cookie`. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getRequestCookie(request: any, name: string): string | undefined {
  const value = request?.cookies?.[name];
  return typeof value === "string" && value ? value : undefined;
}
