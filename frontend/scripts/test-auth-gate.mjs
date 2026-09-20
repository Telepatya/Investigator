import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
assert.match(source, /onClick=\{\(\) => void logout\(\)\}/);
assert.doesNotMatch(source, /onClick=\{\(\) => void logout\}/);
