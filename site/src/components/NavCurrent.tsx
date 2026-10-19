"use client";

import { usePathname } from "next/navigation";
import { useEffect } from "react";

/**
 * Marks the current chapter link with aria-current. When several links match
 * (Start here is a page inside Documents), the longest match wins.
 */
export default function NavCurrent() {
  const path = usePathname();
  useEffect(() => {
    const p = path.endsWith("/") ? path : `${path}/`;
    const links = Array.from(document.querySelectorAll<HTMLAnchorElement>(".chapters a[data-href]"));
    let best: HTMLAnchorElement | null = null;
    for (const a of links) {
      const href = a.dataset.href ?? "";
      if (p.startsWith(href) && href.length > (best?.dataset.href?.length ?? 0)) best = a;
    }
    for (const a of links) {
      if (a === best) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }, [path]);
  return null;
}
