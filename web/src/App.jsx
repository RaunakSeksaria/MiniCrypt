import { useMemo, useState } from "react";
import { buildSourcePrimitive, describeChain, primitives, reduceWithBlackBox, shortestPath } from "./reductions";

function StepList({ title, steps }) {
  return (
    <div className="panel">
      <h3>{title}</h3>
      <ul>
        {steps.map((s, i) => (
          <li key={i} className={`step-${s.status || "ok"}`}>
            {s.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function App() {
  const [foundation, setFoundation] = useState("AES-128");
  const [primitiveA, setPrimitiveA] = useState("PRG");
  const [primitiveB, setPrimitiveB] = useState("PRF");
  const [seed, setSeed] = useState("a3f2c1");
  const [query, setQuery] = useState("1011");
  const [direction, setDirection] = useState("forward");
  const [open, setOpen] = useState(true);

  const leftPrimitive = direction === "forward" ? primitiveA : primitiveB;
  const rightPrimitive = direction === "forward" ? primitiveB : primitiveA;

  const sourceObj = useMemo(() => buildSourcePrimitive(foundation, leftPrimitive, seed), [foundation, leftPrimitive, seed]);

  const path = useMemo(() => shortestPath(leftPrimitive, rightPrimitive, direction), [leftPrimitive, rightPrimitive, direction]);
  const proof = useMemo(() => describeChain(path), [path]);

  const reduceSteps = useMemo(() => reduceWithBlackBox(sourceObj, path, query), [sourceObj, path, query]);

  const buildSteps = useMemo(() => {
    return sourceObj.steps;
  }, [sourceObj]);

  const sameSelection = leftPrimitive === rightPrimitive;

  const onChangeLeft = (value) => {
    if (direction === "forward") setPrimitiveA(value);
    else setPrimitiveB(value);
  };

  const onChangeRight = (value) => {
    if (direction === "forward") setPrimitiveB(value);
    else setPrimitiveA(value);
  };

  return (
    <div className="app">
      <header>
        <h1>CS8.401 Minicrypt Clique Explorer</h1>
        <div className="controls">
          <label>
            Foundation
            <select value={foundation} onChange={(e) => setFoundation(e.target.value)}>
              <option>AES-128</option>
              <option>DLP (g^x mod p)</option>
            </select>
          </label>
          <label>
            Mode
            <select value={direction} onChange={(e) => setDirection(e.target.value)}>
              <option value="forward">Forward (A -&gt; B)</option>
              <option value="backward">Backward (B -&gt; A)</option>
            </select>
          </label>
        </div>
      </header>

      <main>
        <section className="column">
          <h2>Column 1: Build</h2>
          <label>
            {direction === "forward" ? "Source Primitive A" : "Source Primitive B"}
            <select value={leftPrimitive} onChange={(e) => onChangeLeft(e.target.value)}>
              {primitives.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </label>
          <label>
            Seed / Key (hex)
            <input value={seed} onChange={(e) => setSeed(e.target.value)} />
          </label>
          <StepList title={`Foundation -> ${leftPrimitive}`} steps={buildSteps} />
        </section>

        <section className="column">
          <h2>Column 2: Reduce</h2>
          <label>
            {direction === "forward" ? "Target Primitive B" : "Target Primitive A"}
            <select value={rightPrimitive} onChange={(e) => onChangeRight(e.target.value)}>
              {primitives.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </label>
          <label>
            Query / Message
            <input value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <StepList title={`${leftPrimitive} -> ${rightPrimitive}`} steps={reduceSteps} />
        </section>
      </main>

      <section className="proof">
        <button onClick={() => setOpen((v) => !v)}>{open ? "Hide" : "Show"} Reduction Chain Summary</button>
        {open && (
          <div>
            {sameSelection && <p className="hint">Select different primitives to see a non-trivial reduction.</p>}
            <p>
              Chain: {foundation}{" -> "}{leftPrimitive} {path ? `-> ${path.slice(1).join(" -> ")}` : "(unavailable)"}
            </p>
            {proof.length === 0 ? (
              <p>No theorem steps to show for this pair yet.</p>
            ) : (
              <ul>
                {proof.map((st, i) => (
                  <li key={i}>
                    {st.from}{" -> "}{st.to} | {st.theorem} | {st.security} | {st.due}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
