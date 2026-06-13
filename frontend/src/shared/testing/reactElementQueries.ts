import { Children, isValidElement, type ReactElement, type ReactNode } from "react";

export type ElementWithProps = ReactElement<Record<string, unknown>>;

export function findElements(
  node: ReactNode,
  predicate: (element: ElementWithProps) => boolean,
): ElementWithProps[] {
  const matches: ElementWithProps[] = [];

  walkReactNode(node, (element) => {
    if (predicate(element)) {
      matches.push(element);
    }
  });

  return matches;
}

export function findByClassName(node: ReactNode, className: string) {
  return findElements(node, (element) =>
    classNames(element.props.className).includes(className),
  );
}

export function textContent(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === "boolean") {
    return "";
  }
  if (typeof node === "string" || typeof node === "number") {
    return String(node);
  }
  if (Array.isArray(node)) {
    return node.map(textContent).join("");
  }
  if (isValidElement(node)) {
    return textContent((node as ElementWithProps).props.children as ReactNode);
  }
  return "";
}

export function callClick(element: ElementWithProps) {
  const onClick = element.props.onClick;
  if (typeof onClick !== "function") {
    throw new Error("React element does not expose an onClick handler");
  }
  onClick({} as never);
}

function walkReactNode(
  node: ReactNode,
  visit: (element: ElementWithProps) => void,
) {
  if (Array.isArray(node)) {
    for (const child of node) {
      walkReactNode(child, visit);
    }
    return;
  }

  if (!isValidElement(node)) {
    return;
  }

  const element = node as ElementWithProps;
  visit(element);
  Children.forEach(element.props.children as ReactNode, (child) =>
    walkReactNode(child, visit),
  );
}

function classNames(value: unknown) {
  return typeof value === "string" ? value.split(/\s+/u).filter(Boolean) : [];
}
