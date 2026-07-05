import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { SEVERITY_COLORS } from "../lib/ui";
import type { Severity } from "../lib/types";

const TACTIC_ORDER: { id: string; name: string; prefixes: string[] }[] = [
  { id: "initial-access", name: "Initial Access", prefixes: ["T1566", "T1190", "T1133"] },
  { id: "execution", name: "Execution", prefixes: ["T1059", "T1204", "T1047", "T1053", "T1127", "T1202", "T1218"] },
  { id: "persistence", name: "Persistence", prefixes: ["T1547", "T1543", "T1546", "T1136", "T1505", "T1098"] },
  { id: "priv-esc", name: "Priv Esc", prefixes: ["T1548", "T1134", "T1068"] },
  { id: "defense-evasion", name: "Defense Evasion", prefixes: ["T1070", "T1036", "T1112", "T1140", "T1564", "T1222", "T1055", "T1620"] },
  { id: "credential-access", name: "Credential Access", prefixes: ["T1003", "T1555", "T1558", "T1552"] },
  { id: "discovery", name: "Discovery", prefixes: ["T1087", "T1082", "T1482", "T1033", "T1057"] },
  { id: "lateral", name: "Lateral Movement", prefixes: ["T1021", "T1570", "T1550"] },
  { id: "collection", name: "Collection", prefixes: ["T1005", "T1560", "T1113"] },
  { id: "c2", name: "Command & Control", prefixes: ["T1071", "T1105", "T1573", "T1572", "T1090", "T1219"] },
  { id: "exfil", name: "Exfiltration", prefixes: ["T1041", "T1567", "T1048"] },
  { id: "impact", name: "Impact", prefixes: ["T1486", "T1490", "T1489", "T1485"] },
];

function tacticFor(technique: string): string {
  const base = technique.split(".")[0];
  for (const t of TACTIC_ORDER) {
    if (t.prefixes.some((p) => base === p || technique.startsWith(p))) return t.id;
  }
  return "execution";
}

export function AttackMatrix({ caseId }: { caseId: string }) {
  const { data } = useQuery({
    queryKey: ["attack-matrix", caseId],
    queryFn: () => api.getAttackMatrix(caseId),
  });
  const techniques = data?.techniques ?? [];

  const byTactic: Record<string, typeof techniques> = {};
  for (const t of techniques) {
    const tac = tacticFor(t.technique);
    (byTactic[tac] ??= []).push(t);
  }

  if (techniques.length === 0) {
    return (
      <div className="text-sm text-ink-400 py-8 text-center">
        No ATT&CK techniques detected yet. Findings mapped to MITRE will appear here.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
      {TACTIC_ORDER.filter((t) => byTactic[t.id]?.length).map((tactic) => (
        <div key={tactic.id} className="bg-base-900/40 rounded-lg p-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-400 mb-1.5">
            {tactic.name}
          </div>
          <div className="space-y-1">
            {byTactic[tactic.id].map((t) => (
              <div
                key={t.technique}
                title={`${t.technique} · ${t.count} finding(s)`}
                className="rounded px-1.5 py-1 text-[11px] font-medium leading-tight"
                style={{
                  background: `${SEVERITY_COLORS[t.max_severity as Severity]}22`,
                  color: SEVERITY_COLORS[t.max_severity as Severity],
                  border: `1px solid ${SEVERITY_COLORS[t.max_severity as Severity]}44`,
                }}
              >
                <div className="truncate">{t.name}</div>
                <div className="opacity-60 text-[9px]">
                  {t.technique} · {t.count}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
