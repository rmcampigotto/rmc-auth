import { getAuthContext } from "./auth-context.decorator";

describe("getAuthContext", () => {
  it("reads ip and user agent", () => {
    expect(getAuthContext({ ip: "1.2.3.4", headers: { "user-agent": "jest" } })).toEqual({ ip: "1.2.3.4", userAgent: "jest" });
  });

  it("falls back to the socket address and ignores missing values", () => {
    expect(getAuthContext({ socket: { remoteAddress: "::1" }, headers: {} })).toEqual({ ip: "::1" });
    expect(getAuthContext(undefined)).toEqual({});
  });
});
