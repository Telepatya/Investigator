import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Sparkles, Loader2 } from "lucide-react";
import { api, wsUrl } from "../lib/api";

export function AnalyzeButton({ caseId, status }: { caseId: string; status?: string }) {
  const qc = useQueryClient();
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState("");
  const [percent, setPercent] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(wsUrl(`/cases/${caseId}/analyze-ws`));
    ws.onmessage = (ev) => {
      const p = JSON.parse(ev.data);
      if (p.phase === "connected") {
        setRunning(p.message === "running");
        return;
      }
      setRunning(!p.done);
      setPhase(p.message || p.phase);
      if (typeof p.percent === "number" && p.percent >= 0) setPercent(p.percent);
      if (p.done) {
        qc.invalidateQueries({ queryKey: ["case", caseId] });
        qc.invalidateQueries({ queryKey: ["report", caseId] });
        qc.invalidateQueries({ queryKey: ["findings", caseId] });
        qc.invalidateQueries({ queryKey: ["attack-matrix", caseId] });
        qc.invalidateQueries({ queryKey: ["entities", caseId] });
        setTimeout(() => {
          setRunning(false);
          setPhase("");
          setPercent(0);
        }, 2500);
      }
    };
    wsRef.current = ws;
    return () => ws.close();
  }, [caseId, qc]);

  async function start() {
    setRunning(true);
    setPhase("Starting…");
    setPercent(0);
    try {
      await api.startAnalysis(caseId);
    } catch (error) {
      setRunning(false);
      setPhase(error instanceof Error ? error.message : "Analysis could not start");
    }
  }

  const isAnalyzing = running || status === "analyzing";
  const blocked = status === "ingesting";

  return (
    <button
      className="btn-primary relative overflow-hidden"
      onClick={start}
      disabled={isAnalyzing || blocked}
      title={blocked ? "Wait for evidence processing to finish" : "Run AI analysis"}
    >
      {isAnalyzing ? (
        <>
          <Loader2 size={16} className="animate-spin" />
          <span className="max-w-[160px] truncate">{phase || "Analyzing…"}</span>
          {percent > 0 && (
            <span
              className="absolute bottom-0 left-0 h-0.5 bg-base-900/60"
              style={{ width: `${percent}%` }}
            />
          )}
        </>
      ) : (
        <>
          <Sparkles size={16} /> Run AI analysis
        </>
      )}
    </button>
  );
}
