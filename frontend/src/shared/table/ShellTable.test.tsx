import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ShellTable, nextSelectedRowIds } from "./ShellTable";

describe("ShellTable scroll behavior", () => {
  it("renders a reusable scroll region around wide table content", () => {
    const markup = renderToStaticMarkup(
      <ShellTable
        columns={[
          { key: "process", label: "Process" },
          { key: "destination", label: "Destination" },
          { key: "protocol", label: "Protocol" },
          { key: "risk", label: "Risk" },
        ]}
        rows={[
          {
            id: "flow:1",
            cells: {
              destination: "redacted destination",
              process: "powershell.exe",
              protocol: "TLS",
              risk: "high",
            },
            severity: "high",
          },
        ]}
      />,
    );

    expect(markup).toContain("shell-table-scroll scroll-region table-scroll-region");
    expect(markup).toContain("--shell-table-min-width:720px");
    expect(markup).toContain("role=\"table\"");
    expect(markup).toContain("aria-multiselectable=\"true\"");
    expect(markup).toContain("data-severity=\"high\"");
  });

  it("keeps single, ctrl, and shift row selection deterministic", () => {
    const rowIds = ["finding:one", "finding:two", "finding:three", "finding:four"];

    expect(
      nextSelectedRowIds({
        anchorRowId: "finding:one",
        ctrlKey: false,
        rowId: "finding:two",
        rowIds,
        selectedRowIds: [],
        shiftKey: false,
      }),
    ).toEqual(["finding:two"]);

    expect(
      nextSelectedRowIds({
        anchorRowId: "finding:two",
        ctrlKey: true,
        rowId: "finding:three",
        rowIds,
        selectedRowIds: ["finding:two"],
        shiftKey: false,
      }),
    ).toEqual(["finding:two", "finding:three"]);

    expect(
      nextSelectedRowIds({
        anchorRowId: "finding:two",
        ctrlKey: true,
        rowId: "finding:two",
        rowIds,
        selectedRowIds: ["finding:two", "finding:three"],
        shiftKey: false,
      }),
    ).toEqual(["finding:three"]);

    expect(
      nextSelectedRowIds({
        anchorRowId: "finding:two",
        ctrlKey: false,
        rowId: "finding:four",
        rowIds,
        selectedRowIds: ["finding:two"],
        shiftKey: true,
      }),
    ).toEqual(["finding:two", "finding:three", "finding:four"]);
  });
});
