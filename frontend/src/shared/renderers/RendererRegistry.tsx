import type { JsonValue } from "../../bridge/dto/common";
import { UnsupportedContributionRenderer } from "./fallbackRenderers";
import {
  type RendererEntry,
  type RendererRegistryApi,
  type RendererType,
  type UiContributionRendererProps,
} from "./types";

export class RendererRegistry implements RendererRegistryApi {
  private readonly renderers = new Map<RendererType, RendererEntry>();
  private unsupportedEntry: RendererEntry = {
    rendererType: "unsupported",
    label: "Unsupported contribution",
    component: UnsupportedContributionRenderer,
  };

  registerRenderer(entry: RendererEntry) {
    assertRendererEntry(entry);
    this.renderers.set(entry.rendererType, entry);
  }

  resolveRenderer(rendererType: RendererType) {
    return this.renderers.get(rendererType) ?? this.unsupportedEntry;
  }

  entries() {
    return [...this.renderers.values()];
  }
}

export const defaultRendererRegistry = new RendererRegistry();

export function registerRenderer(entry: RendererEntry) {
  defaultRendererRegistry.registerRenderer(entry);
}

export function resolveRenderer(rendererType: RendererType) {
  return defaultRendererRegistry.resolveRenderer(rendererType);
}

export function UiContributionRenderer({
  contribution,
  manifest,
  data,
  registry = defaultRendererRegistry,
}: UiContributionRendererProps) {
  const entry = registry.resolveRenderer(contribution.renderer_type);
  const context = {
    contribution,
    manifest,
    data: {
      value: data ?? contribution.data_source ?? {},
      schema: contribution.schema,
    },
  };
  const validation = entry.validate?.(context) ?? { valid: true };

  if (!validation.valid) {
    return (
      <UnsupportedContributionRenderer
        {...context}
        data={{
          ...context.data,
          value: {
            validation_error_redacted:
              validation.reasonRedacted ?? "renderer validation failed",
          },
        }}
      />
    );
  }

  const Component = entry.component;
  return <Component {...context} />;
}

function assertRendererEntry(entry: RendererEntry) {
  if (!entry.rendererType.trim()) {
    throw new Error("renderer type is required");
  }

  if (containsUnsafeExecutableShape(entry.rendererType)) {
    throw new Error("renderer type cannot request executable plugin UI");
  }
}

function containsUnsafeExecutableShape(value: string) {
  const normalized = value.toLowerCase();
  return [
    "javascript",
    "script",
    "iframe",
    "dom",
    "bundle",
    "invoke",
  ].some((marker) => normalized.includes(marker));
}

export function makeRendererData(value: JsonValue) {
  return value;
}
