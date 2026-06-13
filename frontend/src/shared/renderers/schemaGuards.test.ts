import { describe, expect, it } from "vitest";
import type { RendererContext } from "./types";
import {
  safeEntries,
  tableColumns,
  validateGraphViewModelLike,
  validateSafeRendererContext,
  validateTableLike,
} from "./schemaGuards";

describe("renderer schema guards", () => {
  it("rejects sensitive markers in contribution data and schema", () => {
    expect(
      validateSafeRendererContext(
        context({
          value: { summary_redacted: "safe metadata" },
          schema: [{ field: "raw_payload" }],
        }),
      ),
    ).toEqual({
      valid: false,
      reasonRedacted: "renderer data contains a sensitive marker",
    });

    expect(
      validateSafeRendererContext(
        context({
          value: { payload_blob: "blocked" },
        }),
      ).valid,
    ).toBe(false);
  });

  it("allows GraphViewModel-like projections and rejects canonical internals", () => {
    expect(
      validateGraphViewModelLike(
        context({
          value: {
            graph_type: "incident_graph",
            nodes: [],
            edges: [],
            paths: [],
          },
        }),
      ).valid,
    ).toBe(true);

    expect(
      validateGraphViewModelLike(
        context({
          value: {
            nodes: [],
            canonical_edge: "not a view model field",
          },
        }),
      ),
    ).toEqual({
      valid: false,
      reasonRedacted: "graph renderer requires GraphViewModel or projection data",
    });
  });

  it("bounds table columns and redacts sensitive fields", () => {
    const rows = [
      {
        id: "row-1",
        process: "powershell.exe",
        api_key_value: "must not display",
        destination: "example.invalid",
      },
    ];

    expect(validateTableLike(context({ value: rows })).valid).toBe(false);
    expect(tableColumns(rows).map((column) => column.key)).toEqual([
      "id",
      "process",
      "destination",
    ]);
    expect(safeEntries(rows[0])).toContainEqual(["api_key_value", "[redacted]"]);
  });
});

function context(data: RendererContext["data"]): RendererContext {
  return {
    contribution: {
      contribution_id: "contribution:test",
      plugin_id: "plugin:test",
      slot: "component_center.detail_panel",
      renderer_type: "table",
      title: "Contribution",
      schema: data.schema,
    },
    data,
  };
}
