"use client";

import { useEffect } from "react";

type MermaidApi = typeof import("mermaid").default;

let api: Promise<MermaidApi> | null = null;
let seq = 0;

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Mermaid theme variables read from the page's CSS tokens, so diagrams follow light and dark. */
function themeVariables() {
  const paper = token("--paper");
  const ink = token("--ink");
  return {
    background: paper,
    mainBkg: token("--surface"),
    primaryColor: token("--surface"),
    primaryTextColor: ink,
    primaryBorderColor: token("--ink-2"),
    secondaryColor: token("--surface-2"),
    tertiaryColor: paper,
    lineColor: token("--ink-2"),
    textColor: ink,
    clusterBkg: token("--surface-2"),
    clusterBorder: token("--rule-strong"),
    edgeLabelBackground: paper,
    titleColor: ink,
    nodeTextColor: ink,
    actorBkg: token("--surface"),
    actorBorder: token("--ink-2"),
    actorTextColor: ink,
    actorLineColor: token("--rule-strong"),
    signalColor: ink,
    signalTextColor: ink,
    labelBoxBkgColor: token("--surface-2"),
    labelBoxBorderColor: token("--rule-strong"),
    labelTextColor: ink,
    loopTextColor: ink,
    noteBkgColor: token("--ochre-wash"),
    noteBorderColor: token("--ochre"),
    noteTextColor: ink,
    activationBkgColor: token("--surface-2"),
    activationBorderColor: token("--ink-2"),
    sequenceNumberColor: paper,
    fontFamily: token("--font-mono-stack") || "monospace",
    fontSize: "13px",
  };
}

async function load(): Promise<MermaidApi> {
  if (!api) api = import("mermaid").then((m) => m.default);
  return api;
}

function decode(b64: string): string {
  return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
}

async function draw(el: HTMLElement) {
  try {
    const mermaid = await load();
    const vars = themeVariables();
    const font = vars.fontFamily;
    // Natural size: wide diagrams scroll inside their box instead of shrinking past legibility.
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: vars,
      fontFamily: font,
      flowchart: { htmlLabels: true, curve: "basis", useMaxWidth: false },
      sequence: {
        showSequenceNumbers: true,
        useMaxWidth: false,
        actorFontFamily: font,
        noteFontFamily: font,
        messageFontFamily: font,
        wrap: true,
      },
    });
    const { svg } = await mermaid.render(`mmd-${++seq}`, decode(el.dataset.mermaid ?? ""));
    el.innerHTML = svg;
    el.dataset.rendered = "1";
  } catch (e) {
    // Leave the source text visible; it is the fallback.
    el.dataset.rendered = "error";
    el.dataset.error = e instanceof Error ? e.message : String(e);
  }
}

/**
 * Draws server-rendered diagram placeholders when they scroll near the
 * viewport, so Mermaid loads only on pages that show a diagram and only when
 * one is about to be seen. Redraws when the color scheme changes.
 */
export default function Mermaid() {
  useEffect(() => {
    const blocks = Array.from(document.querySelectorAll<HTMLElement>("[data-mermaid]"));
    if (!blocks.length) return;
    let queue = Promise.resolve();
    const enqueue = (el: HTMLElement) => {
      queue = queue.then(() => draw(el));
    };
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (!e.isIntersecting) continue;
          io.unobserve(e.target);
          enqueue(e.target as HTMLElement);
        }
      },
      { rootMargin: "600px 0px" },
    );
    for (const b of blocks) io.observe(b);

    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const redraw = () => {
      for (const b of blocks) if (b.dataset.rendered) enqueue(b);
    };
    mq.addEventListener("change", redraw);
    return () => {
      io.disconnect();
      mq.removeEventListener("change", redraw);
    };
  }, []);
  return null;
}
