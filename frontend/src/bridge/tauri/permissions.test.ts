import { describe, expect, it } from "vitest";
import {
  assertCoreCommandAllowed,
  MUTATION_COMMANDS,
  READ_COMMANDS,
} from "./permissions";

describe("Core command allowlist", () => {
  it("accepts every exposed read and mutation command", () => {
    for (const command of [...READ_COMMANDS, ...MUTATION_COMMANDS]) {
      expect(() => assertCoreCommandAllowed(command)).not.toThrow();
    }
  });

  it("rejects direct privileged, storage, and raw content command names", () => {
    for (const command of [
      "firewall_write_rule",
      "qos_apply_policy",
      "sqlite_query",
      "windivert_open_handle",
      "read_raw_packet",
      "read_raw_payload",
      "execute_response_action",
    ]) {
      expect(() => assertCoreCommandAllowed(command)).toThrow(/safe Rust Core bridge/);
    }
  });
});
