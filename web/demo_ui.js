// PA Demo definitions with interactive parameters
const PA_DEFINITIONS = {
  1: { params: [] }, // OWF/PRG (uses random seed)
  2: { params: [] }, // PRF (uses random key/input)
  3: { params: [{name: 'message', label: 'Plaintext Message', default: 'Hello CPA!'}] },
  4: { params: [{name: 'message', label: 'Plaintext Message', default: 'Modes of Operation test!'}] },
  5: { params: [{name: 'message', label: 'Message to Authenticate', default: 'Authenticate me!'}] },
  6: { params: [{name: 'message', label: 'Plaintext Message', default: 'CCA-secure message!'}] },
  7: { params: [{name: 'message', label: 'Message to Hash', default: 'Hello Hash!'}] },
  8: { params: [{name: 'message', label: 'Message to Hash', default: 'Test DLP Hash'}] },
  9: { params: [] }, // Birthday attack
  10: { params: [{name: 'message', label: 'Message to HMAC', default: 'HMAC test message'}] },
  11: { params: [] }, // Diffie-Hellman
  12: { params: [{name: 'message_int', label: 'Textbook RSA Message (Int)', default: '42'}, {name: 'message_pkcs', label: 'PKCS#1 Message (Text)', default: 'RSA!'}] },
  13: { params: [] }, // Miller-Rabin
  14: { params: [] }, // CRT
  15: { params: [{name: 'message', label: 'Message to Sign', default: 'Sign this!'}] },
  16: { params: [{name: 'message_int', label: 'ElGamal Message (Int)', default: '42'}] },
  17: { params: [{name: 'message_int', label: 'CCA-PKC Message (Int)', default: '42'}] },
  18: { params: [{name: 'm0', label: 'Message 0 (Int)', default: '42'}, {name: 'm1', label: 'Message 1 (Int)', default: '99'}, {name: 'b', label: 'Choice Bit (0 or 1)', default: '0'}] },
  19: { params: [] }, // Secure AND (runs truth table)
  20: { params: [] }, // MPC (runs tests)
};

async function runInteractivePADemo(pa) {
  const info = PAS.find(p => p.pa === pa);
  const def = PA_DEFINITIONS[pa];
  
  document.getElementById('modalTitle').textContent = `PA#${pa} — ${info.title}`;
  document.getElementById('modal').classList.add('open');
  
  let html = `<div style="margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border);">`;
  html += `<p style="color: var(--text2); font-size: 13px; margin-bottom: 16px;">${info.desc}</p>`;
  
  // Render input fields if params exist
  if (def.params.length > 0) {
    html += `<div style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 16px;">`;
    def.params.forEach(p => {
      html += `<div class="field" style="margin-bottom: 0;">
        <label>${p.label}</label>
        <input type="text" id="demo_param_${p.name}" value="${p.default}" />
      </div>`;
    });
    html += `</div>`;
  } else {
    html += `<p style="color: var(--accent3); font-size: 12px; font-weight: 500; margin-bottom: 16px;">(No configurable parameters — uses random/default values)</p>`;
  }
  
  html += `<button class="btn btn-primary" style="width: 100%;" onclick="executePADemo(${pa})">▶ Run Demo</button>`;
  html += `</div>`;
  html += `<div id="demoOutputContainer"></div>`;
  
  document.getElementById('modalBody').innerHTML = html;
  
  // Auto-run if no params
  if (def.params.length === 0) {
    executePADemo(pa);
  }
}

async function executePADemo(pa) {
  const def = PA_DEFINITIONS[pa];
  const params = {};
  
  // Collect params
  def.params.forEach(p => {
    const el = document.getElementById(`demo_param_${p.name}`);
    if (el) params[p.name] = el.value;
  });
  
  const outContainer = document.getElementById('demoOutputContainer');
  outContainer.innerHTML = '<div style="text-align:center;padding:20px"><div class="spinner"></div></div>';
  
  try {
    const r = await fetch(API + '/api/demo', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pa, params})
    });
    const data = await r.json();
    if (data.detail) { outContainer.innerHTML = `<pre style="color:var(--red)">${data.detail}</pre>`; return; }
    outContainer.innerHTML = renderDemoResult(pa, data);
  } catch(e) {
    outContainer.innerHTML = `<pre style="color:var(--red)">Error: ${e.message}</pre>`;
  }
}

// Override original runPADemo
window.runPADemo = runInteractivePADemo;
