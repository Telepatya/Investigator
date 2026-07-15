import { Fragment, type ReactNode } from "react";

function inline(text: string, key: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean).map((part, index) => {
    if (part.startsWith("`") && part.endsWith("`")) return <code key={`${key}-${index}`}>{part.slice(1, -1)}</code>;
    if (part.startsWith("**") && part.endsWith("**")) return <strong key={`${key}-${index}`}>{part.slice(2, -2)}</strong>;
    return <Fragment key={`${key}-${index}`}>{part}</Fragment>;
  });
}

/** Intentionally small Markdown renderer: React escapes every model-generated string and raw HTML is never interpreted. */
export function ReverseMarkdown({ content }: { content: string }) {
  const lines = (content || "").replace(/\r\n/g, "\n").split("\n");
  return (
    <div className="space-y-2 text-sm leading-6 text-ink-200">
      {lines.map((line, index) => {
        const heading = line.match(/^(#{1,4})\s+(.*)$/);
        if (heading) {
          const level = heading[1].length;
          const classes = level === 1 ? "text-2xl" : level === 2 ? "mt-6 text-lg" : "mt-4 text-base";
          return <div key={index} className={`${classes} font-bold text-ink-50`}>{inline(heading[2], `h${index}`)}</div>;
        }
        const bullet = line.match(/^\s*[-*]\s+(.*)$/);
        if (bullet) return <div key={index} className="ml-4 flex gap-2"><span className="text-accent-blue">•</span><span>{inline(bullet[1], `b${index}`)}</span></div>;
        if (!line.trim()) return <div key={index} className="h-1" />;
        return <p key={index}>{inline(line, `p${index}`)}</p>;
      })}
    </div>
  );
}

