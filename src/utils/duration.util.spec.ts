import { parseDurationToSeconds } from "./duration.util";

describe("parseDurationToSeconds", () => {
  it.each([
    [900, 900],
    ["900", 900],
    ["30s", 30],
    ["15m", 900],
    ["1h", 3600],
    ["1 hour", 3600],
    ["7d", 604800],
    ["2w", 1209600],
    ["1.5h", 5400],
  ])("parses %p", (input, expected) => {
    expect(parseDurationToSeconds(input)).toBe(expected);
  });

  it.each([0, -1, "abc", "10y", "", NaN])("rejects %p", (input) => {
    expect(() => parseDurationToSeconds(input as string | number)).toThrow();
  });
});
