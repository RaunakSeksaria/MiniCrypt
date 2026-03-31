export const primitives = ["OWF", "PRG", "OWP", "PRF", "PRP", "MAC", "CRHF", "HMAC", "CPA-Enc", "CCA-Enc"];

export const paDue = {
  OWF: "PA#1",
  PRG: "PA#1",
  OWP: "PA#1",
  PRF: "PA#2",
  PRP: "PA#4",
  MAC: "PA#5",
  CRHF: "PA#8",
  HMAC: "PA#10",
  "CPA-Enc": "PA#3",
  "CCA-Enc": "PA#6"
};

// PA#0 should support partial implementation gracefully.
const implemented = {
  OWF: true,
  PRG: true,
  OWP: true,
  PRF: true,
  PRP: true,
  MAC: true,
  CRHF: true,
  HMAC: true,
  "CPA-Enc": true,
  "CCA-Enc": true
};

// Forward-only directed reduction graph.
const forwardEdges = {
  OWF: ["PRG", "OWP"],
  OWP: ["PRG"],
  PRG: ["PRF"],
  PRF: ["PRP", "MAC"],
  PRP: ["MAC"],
  CRHF: ["HMAC", "MAC"],
  HMAC: ["MAC", "CCA-Enc"],
  "CPA-Enc": ["CCA-Enc"],
  MAC: ["CCA-Enc"],
  "CCA-Enc": []
};

const theoremByStep = {
  "OWF->PRG": "HILL hard-core-bit construction",
  "OWF->OWP": "OWF to OWP embedding",
  "OWP->PRG": "Hard-core predicate expansion",
  "PRG->PRF": "GGM tree",
  "PRF->PRP": "Luby-Rackoff Feistel",
  "PRF->MAC": "PRF-MAC",
  "PRP->MAC": "PRP/PRF switching + MAC",
  "CRHF->HMAC": "HMAC construction",
  "CRHF->MAC": "CRHF to HMAC to MAC",
  "HMAC->MAC": "HMAC EUF-CMA theorem",
  "HMAC->CCA-Enc": "Encrypt-then-HMAC",
  "MAC->CCA-Enc": "Encrypt-then-MAC",
  "CPA-Enc->CCA-Enc": "Authenticate ciphertexts"
};

function hexSeed(seedHex) {
  const clean = (seedHex || "a3f2c1").replace(/[^0-9a-f]/gi, "").toLowerCase();
  return clean.length ? clean : "a3f2c1";
}

function pseudoHex(input, take = 8) {
  let h = 0x9e3779b9;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = (h * 0x85ebca6b) >>> 0;
    h ^= h >>> 13;
  }
  return h.toString(16).padStart(8, "0").slice(0, take);
}

function reverseGraph(g) {
  const out = {};
  for (const p of primitives) out[p] = [];
  for (const [a, list] of Object.entries(g)) {
    for (const b of list) out[b].push(a);
  }
  return out;
}

function bfsPath(graph, start, end) {
  if (start === end) return [start];
  const q = [[start]];
  const seen = new Set([start]);
  while (q.length) {
    const path = q.shift();
    const last = path[path.length - 1];
    for (const nxt of graph[last] || []) {
      if (seen.has(nxt)) continue;
      const np = [...path, nxt];
      if (nxt === end) return np;
      seen.add(nxt);
      q.push(np);
    }
  }
  return null;
}

export function shortestPath(start, end, direction = "forward") {
  const graph = direction === "backward" ? reverseGraph(forwardEdges) : forwardEdges;
  return bfsPath(graph, start, end);
}

export function describeChain(path) {
  if (!path || path.length < 2) return [];
  return path.slice(0, -1).map((a, i) => {
    const b = path[i + 1];
    const key = `${a}->${b}`;
    return {
      from: a,
      to: b,
      theorem: theoremByStep[key] || "Composed reduction",
      security: "If an adversary breaks target with advantage eps, a reduction breaks source with eps' >= eps/poly(q)",
      due: `${paDue[a]} -> ${paDue[b]}`
    };
  });
}

function baseEval(primitive, keySeed) {
  return (input) => `${primitive}:${pseudoHex(`${keySeed}|${input}|${primitive}`)}...`;
}

export function buildSourcePrimitive(foundation, source, seedHex) {
  const seed = hexSeed(seedHex);
  const steps = [];
  if (!implemented[source]) {
    steps.push({ text: `Not implemented yet (due: ${paDue[source]})`, status: "stub" });
    return {
      primitive: source,
      implemented: false,
      steps,
      evaluate: () => `stub:${source}`
    };
  }

  if (foundation === "AES-128") {
    steps.push({ text: `Foundation key k = ${seed}`, status: "ok" });
    steps.push({ text: `AES(k, 0) = ${pseudoHex(`${seed}:0`, 10)}...`, status: "ok" });
    steps.push({ text: `AES(k, 1) = ${pseudoHex(`${seed}:1`, 10)}...`, status: "ok" });
  } else {
    steps.push({ text: `Foundation exponent x = ${seed}`, status: "ok" });
    steps.push({ text: `g^x mod p = ${pseudoHex(`${seed}:gx`, 10)}...`, status: "ok" });
  }

  steps.push({ text: `Build ${source} (${paDue[source]}) from ${foundation}`, status: "ok" });
  return {
    primitive: source,
    implemented: true,
    steps,
    evaluate: baseEval(source, `${foundation}|${seed}`)
  };
}

export function reduceWithBlackBox(sourceObj, path, query) {
  if (!path) {
    return [
      {
        text: "No supported path in this direction. Try toggling Forward/Backward.",
        status: "warn"
      }
    ];
  }
  if (!sourceObj.implemented) {
    return [{ text: "Source primitive is not implemented, reduction cannot proceed.", status: "stub" }];
  }

  const out = [];
  let current = sourceObj.evaluate(query);
  out.push({ text: `Oracle ${path[0]}(${query}) = ${current}`, status: "ok" });

  for (let i = 0; i < path.length - 1; i++) {
    const from = path[i];
    const to = path[i + 1];
    const theorem = theoremByStep[`${from}->${to}`] || "composed reduction";
    current = `${to}:${pseudoHex(`${current}|${from}|${to}`)}...`;
    out.push({ text: `${from} -> ${to} via ${theorem}`, status: "ok" });
    out.push({ text: `${to} output = ${current}`, status: "ok" });
    if (!implemented[to]) {
      out.push({ text: `Not implemented yet (due: ${paDue[to]})`, status: "stub" });
      break;
    }
  }
  return out;
}
