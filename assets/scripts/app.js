/* Kali4Us app.js
   - Tabs: Commands | Dork Builder | Password & Policy
   - Header clean: compact on small scroll, hide on scroll down, show on scroll up
   - Go to Top: instant, no focus on search
   - Commands: search + chips + copy + toast
   - Dork Builder: domain → safe queries + copy
   - Password Tool: password/passphrase generator + strength + policy template (offline)
*/

(() => {
  "use strict";

  const els = {
    header: document.getElementById("siteHeader"),

    // Tabs / views
    tabCommands: document.getElementById("tabCommands"),
    tabDorks: document.getElementById("tabDorks"),
    tabPassword: document.getElementById("tabPassword"),
    tabHash: document.getElementById("tabHash"),
    tabCodec: document.getElementById("tabCodec"),

    // Commands UI
    q: document.getElementById("q"),
    clear: document.getElementById("clear"),
    chips: document.getElementById("chips"),
    results: document.getElementById("results"),
    count: document.getElementById("count"),
    filterHint: document.getElementById("filterHint"),

    // Dork UI
    dorkDomain: document.getElementById("dorkDomain"),
    dorkKeyword: document.getElementById("dorkKeyword"),
    dorkFiletype: document.getElementById("dorkFiletype"),
    dorkGen: document.getElementById("dorkGen"),
    dorkClear: document.getElementById("dorkClear"),
    dorkResults: document.getElementById("dorkResults"),

    // Password UI
    pwMode: document.getElementById("pwMode"),
    pwGenerate: document.getElementById("pwGenerate"),
    pwCopy: document.getElementById("pwCopy"),
    pwOutput: document.getElementById("pwOutput"),
    pwStrengthFill: document.getElementById("pwStrengthFill"),
    pwStrengthLabel: document.getElementById("pwStrengthLabel"),
    pwEntropyLabel: document.getElementById("pwEntropyLabel"),
    pwOptsPassword: document.getElementById("pwOptsPassword"),
    pwOptsPassphrase: document.getElementById("pwOptsPassphrase"),
    pwLen: document.getElementById("pwLen"),
    pwLower: document.getElementById("pwLower"),
    pwUpper: document.getElementById("pwUpper"),
    pwNums: document.getElementById("pwNums"),
    pwSyms: document.getElementById("pwSyms"),
    ppWords: document.getElementById("ppWords"),
    ppSep: document.getElementById("ppSep"),
    ppCap: document.getElementById("ppCap"),
    ppAddNum: document.getElementById("ppAddNum"),
    polBuild: document.getElementById("polBuild"),
    polCopy: document.getElementById("polCopy"),
    polMinLen: document.getElementById("polMinLen"),
    polMfa: document.getElementById("polMfa"),
    polLock: document.getElementById("polLock"),
    polReuse: document.getElementById("polReuse"),
    polOut: document.getElementById("polOut"),


    tabCvss: document.getElementById("tabCvss"),

cvssAV: document.getElementById("cvssAV"),
cvssAC: document.getElementById("cvssAC"),
cvssPR: document.getElementById("cvssPR"),
cvssUI: document.getElementById("cvssUI"),
cvssS: document.getElementById("cvssS"),
cvssC: document.getElementById("cvssC"),
cvssI: document.getElementById("cvssI"),
cvssA: document.getElementById("cvssA"),
cvssCalc: document.getElementById("cvssCalc"),
cvssCopyVector: document.getElementById("cvssCopyVector"),
cvssScoreLabel: document.getElementById("cvssScoreLabel"),
cvssSeverityLabel: document.getElementById("cvssSeverityLabel"),
cvssBarFill: document.getElementById("cvssBarFill"),
cvssVector: document.getElementById("cvssVector"),



dockHash: document.getElementById("dockHash"),

hashInput: document.getElementById("hashInput"),
hashIdentify: document.getElementById("hashIdentify"),
hashIdClear: document.getElementById("hashIdClear"),
hashIdOut: document.getElementById("hashIdOut"),
hashIdCopy: document.getElementById("hashIdCopy"),

hashAlg: document.getElementById("hashAlg"),
hashText: document.getElementById("hashText"),
hashTextBtn: document.getElementById("hashTextBtn"),
hashFile: document.getElementById("hashFile"),
hashFileBtn: document.getElementById("hashFileBtn"),
hashOut: document.getElementById("hashOut"),
hashOutCopy: document.getElementById("hashOutCopy"),


dockCodec: document.getElementById("dockCodec"),

b64In: document.getElementById("b64In"),
b64Out: document.getElementById("b64Out"),
b64Enc: document.getElementById("b64Enc"),
b64Dec: document.getElementById("b64Dec"),
b64Copy: document.getElementById("b64Copy"),
b64Clear: document.getElementById("b64Clear"),

urlIn: document.getElementById("urlIn"),
urlOut: document.getElementById("urlOut"),
urlEnc: document.getElementById("urlEnc"),
urlDec: document.getElementById("urlDec"),
urlCopy: document.getElementById("urlCopy"),
urlClear: document.getElementById("urlClear"),

hexIn: document.getElementById("hexIn"),
hexOut: document.getElementById("hexOut"),
hexEnc: document.getElementById("hexEnc"),
hexDec: document.getElementById("hexDec"),
hexCopy: document.getElementById("hexCopy"),
hexClear: document.getElementById("hexClear"),


    // misc
    toast: document.getElementById("toast"),
    footerYear: document.getElementById("footerYear"),
    toTop: document.getElementById("toTop"),
  };

  let ALL = [];
  let activeCategory = "All";

  const FALLBACK = [
    { name: "nmap basic scan", cmd: "nmap 192.168.1.1", category: "Recon", desc: "Basic TCP scan", tags: ["scan","network"] },
    { name: "nmap service detection", cmd: "nmap -sV 192.168.1.1", category: "Recon", desc: "Service/version detection", tags: ["scan","service"] },
    { name: "hydra ssh", cmd: "hydra -l user -P wordlist.txt ssh://10.0.0.5", category: "Bruteforce", desc: "SSH password bruteforce", tags: ["password","ssh"] },
    { name: "airmon-ng start", cmd: "airmon-ng start wlan0", category: "Wireless", desc: "Enable monitor mode", tags: ["wifi","monitor"] },
  ];

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function showToast(msg) {
    if (!els.toast) return;
    els.toast.textContent = msg;
    els.toast.classList.add("show");
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => els.toast.classList.remove("show"), 1500);
  }

  function normalize(s) { return String(s || "").toLowerCase().trim(); }
  function tokenize(s) { const t = normalize(s); return t ? t.split(/\s+/g).filter(Boolean) : []; }

  function highlight(text, queryTokens) {
    const raw = String(text || "");
    if (!queryTokens.length) return escapeHtml(raw);

    let safe = escapeHtml(raw);
    const tokens = [...queryTokens].sort((a, b) => b.length - a.length);

    for (const tok of tokens) {
      if (tok.length < 2) continue;
      const re = new RegExp(`(${tok.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "ig");
      safe = safe.replace(re, "<mark>$1</mark>");
    }
    return safe;
  }

  async function copyText(text) {
    const val = String(text || "");
    try {
      await navigator.clipboard.writeText(val);
      showToast("Copied!");
    } catch {
      showToast("Copy failed");
    }
  }

  /* =======================
     Tabs
  ======================= */
  function setView(view) {
   const v = (view === "dork" || view === "password" || view === "cvss" || view === "hash" || view === "codec") ? view : "commands";



    document.body.dataset.view = v;

    els.tabCommands?.setAttribute("aria-selected", String(v === "commands"));
    els.tabDorks?.setAttribute("aria-selected", String(v === "dork"));
    els.tabPassword?.setAttribute("aria-selected", String(v === "password"));
    els.tabCvss?.setAttribute("aria-selected", String(v === "cvss"));
    els.tabHash?.setAttribute("aria-selected", String(v === "hash"));
    els.tabCodec?.setAttribute("aria-selected", String(v === "codec"));



    // avoid cursor popping up on mobile
    document.activeElement?.blur?.();

    try { localStorage.setItem("kali4us_view", v); } catch {}
  }

  function initTabs() {
    let saved = null;
    try { saved = localStorage.getItem("kali4us_view"); } catch {}
    setView(saved || "commands");

    els.tabCommands?.addEventListener("click", () => setView("commands"));
    els.tabDorks?.addEventListener("click", () => setView("dork"));
    els.tabPassword?.addEventListener("click", () => setView("password"));
    els.tabCvss?.addEventListener("click", () => setView("cvss"));
    els.tabHash?.addEventListener("click", () => setView("hash"));
    els.tabCodec?.addEventListener("click", () => setView("codec"));



  }

  /* =======================
     Commands
  ======================= */
  function uniqueCategories(items) {
    const set = new Set();
    for (const it of items) if (it?.category) set.add(String(it.category));
    return ["All", ...Array.from(set).sort((a,b)=>a.localeCompare(b))];
  }

  function renderChips(categories) {
    if (!els.chips) return;
    els.chips.innerHTML = "";
    for (const cat of categories) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chip";
      btn.textContent = cat;
      btn.setAttribute("aria-pressed", String(cat === activeCategory));
      btn.addEventListener("click", () => {
        activeCategory = cat;
        updateCommands();
        [...els.chips.querySelectorAll(".chip")].forEach((c) => {
          c.setAttribute("aria-pressed", String(c.textContent === activeCategory));
        });
      });
      els.chips.appendChild(btn);
    }
  }

  function matchesQuery(item, tokens) {
    if (!tokens.length) return true;
    const hay = normalize([item.name, item.cmd, item.desc, item.category, ...(item.tags||[])].join(" "));
    return tokens.every((t) => hay.includes(t));
  }

  function filterItems() {
    const tokens = tokenize(els.q?.value);
    return ALL.filter((it) => {
      if (activeCategory !== "All" && String(it.category) !== activeCategory) return false;
      return matchesQuery(it, tokens);
    });
  }

  function renderCommands(items) {
    const tokens = tokenize(els.q?.value);

    if (!els.results) return;

    if (!items.length) {
      els.results.innerHTML = `
        <div class="empty">
          <b>No results</b>
          <div class="small">Try a different keyword or choose another category.</div>
        </div>
      `;
      return;
    }

    els.results.innerHTML = "";
    for (const it of items) {
      const article = document.createElement("article");
      article.className = "item";

      const tagList = [
        it.category ? String(it.category) : null,
        ...(Array.isArray(it.tags) ? it.tags.map(String) : []),
      ].filter(Boolean);

      article.innerHTML = `
        <div class="itemTitle">
          <b title="${escapeHtml(it.name || "")}">${highlight(it.name || "", tokens)}</b>
          <span title="${escapeHtml(it.desc || "")}">${highlight(it.desc || "", tokens)}</span>
        </div>

        ${tagList.length ? `
          <div class="tags">
            ${tagList.slice(0, 6).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join("")}
          </div>
        ` : ""}

        <pre>${highlight(it.cmd || "", tokens)}</pre>

        <div class="btnRow">
          <button class="btn" type="button">Copy</button>
        </div>
      `;

      article.querySelector("button")?.addEventListener("click", () => copyText(it.cmd));
      els.results.appendChild(article);
    }
  }

  function updateMeta(visibleCount, totalCount) {
    if (els.count) els.count.textContent = `${visibleCount} / ${totalCount} commands`;

    const q = normalize(els.q?.value);
    const parts = [];
    if (activeCategory !== "All") parts.push(`Category: ${activeCategory}`);
    if (q) parts.push(`Query: "${(els.q?.value || "").trim()}"`);
    if (els.filterHint) els.filterHint.textContent = parts.length ? parts.join(" • ") : "Showing all";
  }

  function updateCommands() {
    const filtered = filterItems();
    renderCommands(filtered);
    updateMeta(filtered.length, ALL.length);
    els.clear?.classList.toggle("show", !!normalize(els.q?.value));
  }

  async function loadCommands() {
    try {
      const res = await fetch("commands.json", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const list = Array.isArray(data) ? data : Array.isArray(data.commands) ? data.commands : null;
      if (!list) throw new Error("Invalid commands.json format");

      ALL = list.map((x) => ({
        name: x.name ?? x.title ?? "",
        cmd: x.cmd ?? x.command ?? "",
        category: x.category ?? x.group ?? "Uncategorized",
        desc: x.desc ?? x.description ?? "",
        tags: Array.isArray(x.tags) ? x.tags : [],
      }));
    } catch {
      ALL = FALLBACK;
    }

    renderChips(uniqueCategories(ALL));
    updateCommands();
  }

  function initCommandsEvents() {
    els.q?.addEventListener("input", updateCommands);
    els.clear?.addEventListener("click", () => {
      if (!els.q) return;
      els.q.value = "";
      updateCommands();
      document.activeElement?.blur?.();
    });
  }

  /* =======================
     Dork Builder (safe queries)
  ======================= */
  function normalizeDomain(raw) {
    let d = String(raw || "").trim().toLowerCase();
    d = d.replace(/^https?:\/\//, "");
    d = d.replace(/^www\./, "");
    d = d.split("/")[0];
    d = d.split("?")[0];
    d = d.split("#")[0];
    return d;
  }
  function isValidDomain(d) {
    if (!d || d.length > 253) return false;
    if (!d.includes(".")) return false;
    return /^[a-z0-9.-]+$/.test(d) && !d.includes("..") && !d.startsWith("-") && !d.endsWith("-");
  }
  function buildDorkQueries({ domain, keyword, filetype }) {
    const site = `site:${domain}`;
    const kw = keyword ? ` ("${keyword.replace(/"/g, "")}")` : "";
    const ft = filetype ? ` filetype:${filetype}` : "";

    const base = [
      `${site}${kw}${ft}`,
      `${site} (sitemap.xml OR robots.txt)`,
      `${site} (privacy OR "terms" OR "acceptable use")`,
      `${site} ("security.txt" OR "responsible disclosure" OR "bug bounty")`,
      `${site} (contact OR support OR help)`,
      `${site} (inurl:docs OR inurl:documentation OR inurl:developer)`,
      `${site} (inurl:status OR "system status" OR uptime)`,
      `${site} (inurl:api OR "API reference")`,
      `${site} (inurl:blog OR news OR updates)`,
      `${site} (careers OR jobs OR hiring)`,
      `${site} -www.${domain}`,
      `site:*.${domain} -site:www.${domain}`,
    ];

    if (filetype) {
      base.unshift(`${site} filetype:${filetype}`);
      base.unshift(`${site} "${domain}" filetype:${filetype}`);
    }

    return Array.from(new Set(base)).slice(0, 20);
  }
  function renderDorks(queries) {
    if (!els.dorkResults) return;

    if (!queries.length) {
      els.dorkResults.innerHTML = `
        <div class="empty">
          <b>No queries</b>
          <div class="small">Enter a valid domain (example.com).</div>
        </div>
      `;
      return;
    }

    els.dorkResults.innerHTML = "";
    for (const q of queries) {
      const card = document.createElement("div");
      card.className = "dorkItem";
      card.innerHTML = `
        <code>${escapeHtml(q)}</code>
        <div class="btnRow">
          <button class="btn" type="button">Copy</button>
        </div>
      `;
      card.querySelector("button")?.addEventListener("click", () => copyText(q));
      els.dorkResults.appendChild(card);
    }
  }
  function generateDorks() {
    const domain = normalizeDomain(els.dorkDomain?.value);
    const keyword = String(els.dorkKeyword?.value || "").trim();
    const filetype = String(els.dorkFiletype?.value || "").trim();

    if (!isValidDomain(domain)) {
      renderDorks([]);
      showToast("Enter a valid domain (example.com)");
      return;
    }

    renderDorks(buildDorkQueries({ domain, keyword, filetype }));
  }
  function initDorkBuilder() {
    els.dorkGen?.addEventListener("click", generateDorks);
    els.dorkDomain?.addEventListener("keydown", (e) => { if (e.key === "Enter") generateDorks(); });
    els.dorkKeyword?.addEventListener("keydown", (e) => { if (e.key === "Enter") generateDorks(); });

    els.dorkClear?.addEventListener("click", () => {
      if (els.dorkDomain) els.dorkDomain.value = "";
      if (els.dorkKeyword) els.dorkKeyword.value = "";
      if (els.dorkFiletype) els.dorkFiletype.value = "";
      if (els.dorkResults) els.dorkResults.innerHTML = "";
      document.activeElement?.blur?.();
    });
  }

  /* =======================
     Password / Passphrase Generator + Policy (offline)
  ======================= */

  // Small offline word list (extend anytime)
  const WORDS = [
    "amber","anchor","atlas","autumn","bamboo","banner","beacon","biscuit","blossom","bravo",
    "canyon","carbon","cashew","cello","cinder","cobalt","comet","crimson","delta","dune",
    "ember","falcon","fennec","frost","galaxy","ginger","glacier","harbor","honey","indigo",
    "jigsaw","juniper","krypton","lagoon","lantern","lemon","lilac","mango","marble","matrix",
    "nebula","nectar","obsidian","octave","olive","onyx","orbit","panda","pebble","phoenix",
    "quartz","radar","raven","rocket","saffron","sailor","shadow","silver","solstice","sparrow",
    "tango","thunder","topaz","tulip","vector","violet","walnut","whisper","winter","zephyr"
  ];

  function randInt(maxExclusive) {
    // secure random integer in [0, maxExclusive)
    if (maxExclusive <= 0) return 0;
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    let x;
    do {
      crypto.getRandomValues(buf);
      x = buf[0];
    } while (x >= limit);
    return x % maxExclusive;
  }

  function pick(list) {
    return list[randInt(list.length)];
  }

  function randomFromCharset(charset, len) {
    const out = [];
    for (let i = 0; i < len; i++) out.push(charset[randInt(charset.length)]);
    return out.join("");
  }

  function buildCharset({ lower, upper, nums, syms }) {
    const lowerSet = "abcdefghijklmnopqrstuvwxyz";
    const upperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numSet = "0123456789";
    const symSet = "!@#$%^&*()-_=+[]{};:,.?";

    let cs = "";
    if (lower) cs += lowerSet;
    if (upper) cs += upperSet;
    if (nums) cs += numSet;
    if (syms) cs += symSet;

    // fallback to lower if user unchecks all
    if (!cs) cs = lowerSet;
    return cs;
  }

  function generatePassword() {
    const len = Math.max(8, Math.min(128, Number(els.pwLen?.value || 16)));
    const cs = buildCharset({
      lower: !!els.pwLower?.checked,
      upper: !!els.pwUpper?.checked,
      nums: !!els.pwNums?.checked,
      syms: !!els.pwSyms?.checked,
    });
    return randomFromCharset(cs, len);
  }

  function titleCase(w) {
    if (!w) return w;
    return w.charAt(0).toUpperCase() + w.slice(1);
  }

  function generatePassphrase() {
    const n = Math.max(3, Math.min(12, Number(els.ppWords?.value || 5)));
    const sep = String(els.ppSep?.value ?? "-");

    const words = [];
    for (let i = 0; i < n; i++) {
      let w = pick(WORDS);
      if (els.ppCap?.checked) w = titleCase(w);
      words.push(w);
    }

    let phrase = words.join(sep);

    if (els.ppAddNum?.checked) {
      const num = String(randInt(100)); // 0-99
      phrase += sep + num;
    }

    return phrase;
  }

  function estimateEntropyBits(text, mode) {
    // Rough estimate:
    // - password: log2(charsetSize^len) = len*log2(charsetSize)
    // - passphrase: words*log2(wordlistSize) (+ small bonus for number)
    if (!text) return 0;

    if (mode === "passphrase") {
      const wordCount = Math.max(1, (text.match(/[A-Za-z]+/g) || []).length);
      const base = wordCount * Math.log2(WORDS.length);
      const hasNum = /\d/.test(text) ? Math.log2(100) : 0;
      const hasSym = /[^A-Za-z0-9\s]/.test(text) ? 6 : 0; // tiny bonus
      return base + hasNum + hasSym;
    }

    // password mode: infer charset size from used character classes
    let charset = 0;
    if (/[a-z]/.test(text)) charset += 26;
    if (/[A-Z]/.test(text)) charset += 26;
    if (/\d/.test(text)) charset += 10;
    if (/[^A-Za-z0-9\s]/.test(text)) charset += 28; // approx
    if (charset <= 0) charset = 26;

    return text.length * Math.log2(charset);
  }

  function scoreStrength(text, mode) {
    // Practical scoring: 0..100 based on entropy + length
    const entropy = estimateEntropyBits(text, mode);
    const len = (text || "").length;

    let score = 0;

    // entropy dominates
    score += Math.min(80, entropy); // 0..80
    // length bonus
    score += Math.min(20, Math.max(0, len - 8)); // up to +20

    score = Math.max(0, Math.min(100, Math.round(score)));

    let label = "Weak";
    if (score >= 80) label = "Strong";
    else if (score >= 60) label = "Good";
    else if (score >= 40) label = "Okay";

    return { score, label, entropy: Math.round(entropy) };
  }

  function renderStrength(text) {
    const mode = String(els.pwMode?.value || "password");
    const { score, label, entropy } = scoreStrength(text, mode);

    if (els.pwStrengthFill) els.pwStrengthFill.style.width = `${score}%`;
    if (els.pwStrengthLabel) els.pwStrengthLabel.textContent = `Strength: ${label} (${score}/100)`;
    if (els.pwEntropyLabel) els.pwEntropyLabel.textContent = `Entropy: ~${entropy} bits`;
  }

  function setPwModeUI(mode) {
    const m = mode === "passphrase" ? "passphrase" : "password";
    if (els.pwOptsPassword) els.pwOptsPassword.style.display = (m === "password") ? "block" : "none";
    if (els.pwOptsPassphrase) els.pwOptsPassphrase.style.display = (m === "passphrase") ? "block" : "none";
  }

  function buildPolicyText() {
    const minLen = Math.max(8, Math.min(128, Number(els.polMinLen?.value || 14)));
    const mfa = String(els.polMfa?.value || "required");
    const lock = Math.max(3, Math.min(50, Number(els.polLock?.value || 10)));
    const reuse = String(els.polReuse?.value || "disallow");

    const mfaLine = (mfa === "required")
      ? "MFA is REQUIRED for all user accounts where supported (prefer phishing-resistant methods)."
      : "MFA is RECOMMENDED for all user accounts; REQUIRED for admin and high-risk access.";

    const reuseLine = (reuse === "disallow")
      ? "Password reuse is NOT allowed across systems. Enforce history and block known-breached passwords."
      : "Password reuse is allowed (not recommended). Prefer enforcing history + breached-password checks.";

    return [
      "PASSWORD & AUTHENTICATION POLICY (TEMPLATE)",
      "",
      "1) Scope",
      "Applies to all user accounts, admin accounts, service accounts, and authentication systems managed by the organization.",
      "",
      "2) Password Requirements",
      `- Minimum length: ${minLen} characters.`,
      "- Encourage long passwords/passphrases; do NOT require periodic rotation unless compromise is suspected.",
      "- Block common/weak passwords and known-breached passwords (use a denylist/breach check).",
      reuseLine,
      "",
      "3) MFA Requirements",
      `- ${mfaLine}`,
      "- For privileged/admin access: MFA REQUIRED + step-up for sensitive actions.",
      "",
      "4) Account Lockout / Rate Limiting",
      `- After ${lock} failed login attempts: enforce lockout or progressive delays.`,
      "- Apply rate-limiting and bot protection on authentication endpoints.",
      "",
      "5) Reset & Recovery",
      "- Use secure recovery (verified email/phone or helpdesk identity checks).",
      "- Reset tokens must be single-use, time-limited, and transmitted securely.",
      "",
      "6) Storage & Transmission",
      "- Store passwords using strong salted hashing (e.g., bcrypt/Argon2/PBKDF2) with appropriate parameters.",
      "- Never log passwords. Always transmit credentials over TLS.",
      "",
      "7) Service Accounts / API Keys",
      "- Use unique secrets per service; rotate on compromise or personnel changes.",
      "- Prefer short-lived tokens where possible.",
      "",
      "8) User Guidance",
      "- Recommend password managers.",
      "- Use unique passwords for every system + MFA.",
      "",
      "— End —"
    ].join("\n");
  }
function initCvssCalculator() {
  if (!els.cvssCalc || !els.cvssVector) return;

  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
  const AC = { L: 0.77, H: 0.44 };
  const UI = { N: 0.85, R: 0.62 };
  const CIA = { H: 0.56, L: 0.22, N: 0.00 };

  function prWeight(pr, scope) {
    // CVSS v3.1 PR depends on Scope
    if (scope === "U") {
      return { N: 0.85, L: 0.62, H: 0.27 }[pr];
    }
    return { N: 0.85, L: 0.68, H: 0.50 }[pr];
  }

  function roundUp1(x) {
    // round up to 1 decimal per CVSS spec
    return Math.ceil(x * 10 + 1e-10) / 10;
  }

  function severity(score) {
    if (score === 0) return "None";
    if (score <= 3.9) return "Low";
    if (score <= 6.9) return "Medium";
    if (score <= 8.9) return "High";
    return "Critical";
  }

  function calc() {
    const av = String(els.cvssAV.value);
    const ac = String(els.cvssAC.value);
    const pr = String(els.cvssPR.value);
    const ui = String(els.cvssUI.value);
    const s  = String(els.cvssS.value);
    const c  = String(els.cvssC.value);
    const i  = String(els.cvssI.value);
    const a  = String(els.cvssA.value);

    const iss = 1 - (1 - CIA[c]) * (1 - CIA[i]) * (1 - CIA[a]);

    let impact;
    if (s === "U") {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }

    const exploit = 8.22 * AV[av] * AC[ac] * prWeight(pr, s) * UI[ui];

    let baseScore = 0;
    if (impact > 0) {
      if (s === "U") {
        baseScore = roundUp1(Math.min(impact + exploit, 10));
      } else {
        baseScore = roundUp1(Math.min(1.08 * (impact + exploit), 10));
      }
    }

    const vec = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

    // UI
    els.cvssVector.value = vec;
    els.cvssScoreLabel.textContent = `Base Score: ${baseScore.toFixed(1)}`;
    els.cvssSeverityLabel.textContent = `Severity: ${severity(baseScore)}`;

    if (els.cvssBarFill) {
      // map 0..10 to 0..100
      els.cvssBarFill.style.width = `${Math.round((baseScore / 10) * 100)}%`;
    }

    return { baseScore, vec };
  }

  // Calculate on button + on change
  els.cvssCalc.addEventListener("click", () => {
    calc();
    showToast("Calculated");
    document.activeElement?.blur?.();
  });

  const inputs = [els.cvssAV, els.cvssAC, els.cvssPR, els.cvssUI, els.cvssS, els.cvssC, els.cvssI, els.cvssA];
  inputs.forEach((el) => el.addEventListener("change", () => calc()));

  // Copy vector
  els.cvssCopyVector.addEventListener("click", () => {
    const v = els.cvssVector.value || "";
    if (!v) return showToast("Nothing to copy");
    copyText(v);
  });

  // initial
  calc();
}
function initHashTools() {
  if (!els.hashIdOut || !els.hashOut) return;
  const hashAlgSearch = document.getElementById("hashAlgSearch");

  const isHex = (s) => /^[0-9a-fA-F]+$/.test(s);
  const isB64 = (s) => /^[A-Za-z0-9+/=]+$/.test(s) && s.length % 4 === 0;
  (function initHashAlgSearch() {
  if (!hashAlgSearch || !els.hashAlg) return;

  // store original optgroups/options once
  const original = Array.from(els.hashAlg.children).map((node) => node.cloneNode(true));

  function normalize(s) {
    return String(s || "").toLowerCase().replace(/\s+/g, " ").trim();
  }

  function rebuild(query) {
    const q = normalize(query);

    // restore full list if empty
    els.hashAlg.innerHTML = "";
    if (!q) {
      original.forEach(n => els.hashAlg.appendChild(n.cloneNode(true)));
      return;
    }

    // filter options inside each optgroup
    original.forEach((grp) => {
      if (grp.tagName !== "OPTGROUP") return;

      const newGrp = document.createElement("optgroup");
      newGrp.label = grp.label;

      const opts = Array.from(grp.querySelectorAll("option"));
      opts.forEach((opt) => {
        const text = normalize(opt.textContent);
        const val = normalize(opt.value);
        if (text.includes(q) || val.includes(q)) {
          newGrp.appendChild(opt.cloneNode(true));
        }
      });

      if (newGrp.children.length) els.hashAlg.appendChild(newGrp);
    });

    // if nothing matched, show a disabled hint option
    if (!els.hashAlg.children.length) {
      const og = document.createElement("optgroup");
      og.label = "No matches";
      const o = document.createElement("option");
      o.disabled = true;
      o.textContent = "No algorithm found";
      og.appendChild(o);
      els.hashAlg.appendChild(og);
    }
  }

  // live filter
  hashAlgSearch.addEventListener("input", () => rebuild(hashAlgSearch.value));

  // small UX: ESC clears search
  hashAlgSearch.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      hashAlgSearch.value = "";
      rebuild("");
      hashAlgSearch.blur();
    }
  });
})();

  function guessHashType(raw) {
    const s = String(raw || "").trim();

    if (!s) return "No input.";

    // common prefix-based formats
    if (s.startsWith("$2a$") || s.startsWith("$2b$") || s.startsWith("$2y$")) return "bcrypt ($2x$...)";
    if (s.startsWith("$argon2i$") || s.startsWith("$argon2id$")) return "Argon2 ($argon2...)";
    if (s.startsWith("$pbkdf2-")) return "PBKDF2 (modular crypt format)";
    if (s.startsWith("$scrypt$")) return "scrypt (modular crypt format)";

    // hex length hints
    const clean = s.replace(/^0x/i, "").replace(/\s+/g, "");
    if (isHex(clean)) {
      const n = clean.length;
      const maybe = [];
      if (n === 32) maybe.push("MD5 (128-bit hex)", "NTLM (128-bit hex)");
      if (n === 40) maybe.push("SHA-1 (160-bit hex)");
      if (n === 56) maybe.push("SHA-224 (224-bit hex)");
      if (n === 64) maybe.push("SHA-256 (256-bit hex)");
      if (n === 96) maybe.push("SHA-384 (384-bit hex)");
      if (n === 128) maybe.push("SHA-512 (512-bit hex)");
      if (n === 16) maybe.push("CRC64 / short hash (non-unique)");

      return maybe.length
        ? `Looks like HEX (${n} chars)\nPossible: ${maybe.join(", ")}`
        : `Looks like HEX (${n} chars)\nUnknown hash type (length not common).`;
    }

    // base64-ish blobs
    if (isB64(clean)) {
      return `Looks like Base64 (${clean.length} chars)\nCould be encoded bytes (not necessarily a hash).`;
    }

    return "Unknown format. Not hex/base64 or not a common modular hash string.";
  }

  function setIdOut(text) {
    els.hashIdOut.value = text;
  }

  // Identify
  els.hashIdentify?.addEventListener("click", () => {
    const v = els.hashInput?.value || "";
    setIdOut(guessHashType(v));
    document.activeElement?.blur?.();
  });

  els.hashIdClear?.addEventListener("click", () => {
    if (els.hashInput) els.hashInput.value = "";
    setIdOut("");
    document.activeElement?.blur?.();
  });

  els.hashIdCopy?.addEventListener("click", () => {
    const v = els.hashIdOut.value || "";
    if (!v) return showToast("Nothing to copy");
    copyText(v);
  });

  // Local hashing helpers
  function bufToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  }

  async function digestString(alg, text) {
    const enc = new TextEncoder();
    const data = enc.encode(String(text));
    const hash = await crypto.subtle.digest(alg, data);
    return bufToHex(hash);
  }

  async function digestFile(alg, file) {
    const buf = await file.arrayBuffer();
    const hash = await crypto.subtle.digest(alg, buf);
    return bufToHex(hash);
  }

  // Hash text
  els.hashTextBtn?.addEventListener("click", async () => {
    const alg = String(els.hashAlg?.value || "SHA-256");
    const text = String(els.hashText?.value || "");
    if (!text) return showToast("Enter text first");

    try {
      const out = await digestString(alg, text);
      els.hashOut.value = `${alg}\n${out}`;
      showToast("Hashed");
    } catch {
      showToast("Hash failed");
    } finally {
      document.activeElement?.blur?.();
    }
  });

  // Hash file
  els.hashFileBtn?.addEventListener("click", async () => {
    const alg = String(els.hashAlg?.value || "SHA-256");
    const file = els.hashFile?.files?.[0];
    if (!file) return showToast("Choose a file first");

    try {
      const out = await digestFile(alg, file);
      els.hashOut.value = `${alg}\n${out}\n\nFile: ${file.name} (${file.size} bytes)`;
      showToast("File hashed");
    } catch {
      showToast("File hash failed");
    } finally {
      document.activeElement?.blur?.();
    }
  });

  els.hashOutCopy?.addEventListener("click", () => {
    const v = els.hashOut.value || "";
    if (!v) return showToast("Nothing to copy");
    copyText(v);
  });
}

  function initPasswordTool() {
    if (!els.pwMode) return;

    const updateMode = () => {
      const mode = String(els.pwMode.value || "password");
      setPwModeUI(mode);
      // update strength based on current output
      renderStrength(els.pwOutput?.value || "");
    };

    els.pwMode.addEventListener("change", updateMode);

    els.pwGenerate?.addEventListener("click", () => {
      const mode = String(els.pwMode?.value || "password");
      const out = (mode === "passphrase") ? generatePassphrase() : generatePassword();
      if (els.pwOutput) els.pwOutput.value = out;
      renderStrength(out);
      document.activeElement?.blur?.(); // clean
    });

    els.pwCopy?.addEventListener("click", () => {
      const v = els.pwOutput?.value || "";
      if (!v) return showToast("Nothing to copy");
      copyText(v);
    });

    // update strength when options change
    const optEls = [els.pwLen, els.pwLower, els.pwUpper, els.pwNums, els.pwSyms, els.ppWords, els.ppSep, els.ppCap, els.ppAddNum];
    optEls.forEach((el) => el?.addEventListener("input", () => renderStrength(els.pwOutput?.value || "")));
    optEls.forEach((el) => el?.addEventListener("change", () => renderStrength(els.pwOutput?.value || "")));

    els.polBuild?.addEventListener("click", () => {
      const txt = buildPolicyText();
      if (els.polOut) els.polOut.value = txt;
      showToast("Policy generated");
      document.activeElement?.blur?.();
    });

    els.polCopy?.addEventListener("click", () => {
      const v = els.polOut?.value || "";
      if (!v) return showToast("Nothing to copy");
      copyText(v);
    });

    // initial
    updateMode();
    // pre-generate policy text once
    if (els.polOut) els.polOut.value = buildPolicyText();
  }
function initCodecTools() {
  const opSelect = document.getElementById("chefOpSelect");
  const addOpBtn = document.getElementById("chefAddOp");
  const recipeEl = document.getElementById("chefRecipe");

  const autoRun = document.getElementById("chefAutoRun");
  const runBtn = document.getElementById("chefRun");
  const clearRecipeBtn = document.getElementById("chefClearRecipe");

  const input = document.getElementById("chefIn");
  const output = document.getElementById("chefOut");

  const pasteBtn = document.getElementById("chefPaste");
  const swapBtn = document.getElementById("chefSwap");
  const clearIOBtn = document.getElementById("chefClearIO");
  const copyBtn = document.getElementById("chefCopy");

  const meta = document.getElementById("chefMeta");
  const err = document.getElementById("chefErr");

  if (!opSelect || !addOpBtn || !recipeEl || !input || !output) return;

  const OP_LABEL = {
    to_b64: "To Base64",
    from_b64: "From Base64",
    url_enc: "URL Encode",
    url_dec: "URL Decode",
    to_hex: "Text → Hex",
    from_hex: "Hex → Text",
    html_enc: "HTML Entity Encode",
    html_dec: "HTML Entity Decode",
    json_pretty: "JSON Pretty Print",
    json_min: "JSON Minify",
    trim: "Trim",
    lower: "Lowercase",
    upper: "Uppercase",
    defang: "Defang URL/Domain",
    refang: "Refang URL/Domain",
    jwt_decode: "JWT Decode (no verify)"
  };

  // Unicode-safe Base64
  const b64Encode = (s) => btoa(unescape(encodeURIComponent(String(s))));
  const b64Decode = (s) => decodeURIComponent(escape(atob(String(s))));

  const textToHex = (s) => {
    const bytes = new TextEncoder().encode(String(s));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  };

  const hexToText = (hex) => {
    let h = String(hex || "").trim().toLowerCase();
    h = h.replace(/0x/g, "").replace(/[^0-9a-f]/g, "");
    if (h.length % 2 !== 0) throw new Error("Odd hex length");
    const bytes = new Uint8Array(h.length / 2);
    for (let i = 0; i < h.length; i += 2) bytes[i / 2] = parseInt(h.slice(i, i + 2), 16);
    return new TextDecoder().decode(bytes);
  };

  const htmlEncode = (s) => String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  const htmlDecode = (s) => {
    const t = document.createElement("textarea");
    t.innerHTML = String(s);
    return t.value;
  };

  const defang = (s) => String(s)
    .replaceAll("http://", "hxxp://")
    .replaceAll("https://", "hxxps://")
    .replace(/\./g, "[.]");

  const refang = (s) => String(s)
    .replaceAll("hxxp://", "http://")
    .replaceAll("hxxps://", "https://")
    .replaceAll("[.]", ".")
    .replace(/\s+/g, " ");

  const jwtDecode = (token) => {
    const parts = String(token || "").trim().split(".");
    if (parts.length < 2) throw new Error("Not a JWT");
    const decodeB64Url = (p) => {
      const b64 = p.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((p.length + 3) % 4);
      return b64Decode(b64);
    };
    const header = JSON.parse(decodeB64Url(parts[0]));
    const payload = JSON.parse(decodeB64Url(parts[1]));
    return JSON.stringify({ header, payload }, null, 2);
  };

  const OPS = {
    to_b64: (s) => b64Encode(s),
    from_b64: (s) => b64Decode(s),
    url_enc: (s) => encodeURIComponent(String(s)),
    url_dec: (s) => decodeURIComponent(String(s)),
    to_hex: (s) => textToHex(s),
    from_hex: (s) => hexToText(s),
    html_enc: (s) => htmlEncode(s),
    html_dec: (s) => htmlDecode(s),
    json_pretty: (s) => JSON.stringify(JSON.parse(String(s)), null, 2),
    json_min: (s) => JSON.stringify(JSON.parse(String(s))),
    trim: (s) => String(s).trim(),
    lower: (s) => String(s).toLowerCase(),
    upper: (s) => String(s).toUpperCase(),
    defang: (s) => defang(s),
    refang: (s) => refang(s),
    jwt_decode: (s) => jwtDecode(s),
  };

  let recipe = []; // array of op keys

  function renderRecipe() {
    recipeEl.innerHTML = "";

    if (!recipe.length) {
      recipeEl.innerHTML = `
        <div class="empty">
          <b>No recipe yet</b>
          <div class="small">Pick an operation and tap <b>Add</b>.</div>
        </div>
      `;
      return;
    }

    recipe.forEach((op, idx) => {
      const div = document.createElement("div");
      div.className = "chefStep";
      div.innerHTML = `
        <div class="chefStepName" title="${OP_LABEL[op] || op}">
          ${idx + 1}. ${OP_LABEL[op] || op}
        </div>
        <div class="chefStepBtns">
          <button class="btn secondary chefMini" type="button" data-act="up" data-idx="${idx}">↑</button>
          <button class="btn secondary chefMini" type="button" data-act="down" data-idx="${idx}">↓</button>
          <button class="btn secondary chefMini" type="button" data-act="del" data-idx="${idx}">✕</button>
        </div>
      `;
      recipeEl.appendChild(div);
    });
  }

  function setError(msg) {
    if (!err) return;
    if (!msg) {
      err.style.display = "none";
      err.textContent = "";
      return;
    }
    err.style.display = "block";
    err.textContent = msg;
    err.className = "note"; // keep style
  }

  function setMeta(text) {
    if (!meta) return;
    meta.textContent = text || "—";
  }

  function runRecipe() {
    setError("");
    try {
      let v = input.value || "";
      for (const op of recipe) {
        const fn = OPS[op];
        if (!fn) throw new Error(`Unknown op: ${op}`);
        v = fn(v);
      }
      output.value = String(v);
      setMeta(`${output.value.length} chars • ${recipe.length} step(s)`);
    } catch (e) {
      setError(`Error: ${e && e.message ? e.message : "Failed"}`);
      output.value = "";
      setMeta("—");
    }
  }

  function maybeAutoRun() {
    if (autoRun?.checked) runRecipe();
  }

  addOpBtn.addEventListener("click", () => {
    recipe.push(String(opSelect.value));
    renderRecipe();
    maybeAutoRun();
    document.activeElement?.blur?.();
  });

  recipeEl.addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    const act = btn.getAttribute("data-act");
    const idx = Number(btn.getAttribute("data-idx"));
    if (!Number.isFinite(idx)) return;

    if (act === "del") recipe.splice(idx, 1);
    if (act === "up" && idx > 0) [recipe[idx - 1], recipe[idx]] = [recipe[idx], recipe[idx - 1]];
    if (act === "down" && idx < recipe.length - 1) [recipe[idx + 1], recipe[idx]] = [recipe[idx], recipe[idx + 1]];

    renderRecipe();
    maybeAutoRun();
  });

  runBtn?.addEventListener("click", () => {
    runRecipe();
    showToast("Done");
    document.activeElement?.blur?.();
  });

  clearRecipeBtn?.addEventListener("click", () => {
    recipe = [];
    renderRecipe();
    output.value = "";
    setMeta("—");
    setError("");
    showToast("Recipe cleared");
    document.activeElement?.blur?.();
  });

  input.addEventListener("input", () => {
    setError("");
    if (autoRun?.checked) runRecipe();
  });

  pasteBtn?.addEventListener("click", async () => {
    try {
      const t = await navigator.clipboard.readText();
      input.value = t || "";
      maybeAutoRun();
      showToast("Pasted");
    } catch {
      showToast("Paste blocked");
    } finally {
      document.activeElement?.blur?.();
    }
  });

  swapBtn?.addEventListener("click", () => {
    const a = input.value;
    input.value = output.value;
    output.value = a;
    setError("");
    setMeta("Swapped");
    maybeAutoRun();
    showToast("Swapped");
    document.activeElement?.blur?.();
  });

  clearIOBtn?.addEventListener("click", () => {
    input.value = "";
    output.value = "";
    setMeta("—");
    setError("");
    showToast("Cleared");
    document.activeElement?.blur?.();
  });

  copyBtn?.addEventListener("click", () => {
    const v = output.value || "";
    if (!v) return showToast("Nothing to copy");
    copyText(v);
  });

  // init
  renderRecipe();
  setMeta("—");
  setError("");
}



  /* =======================
     Scroll: compact + hide/show + toTop
  ======================= */
  function initScrollUX() {
    let lastY = window.scrollY || 0;
    let ticking = false;

    function onScrollFrame() {
      const y = window.scrollY || 0;
      const delta = y - lastY;

      if (els.toTop) els.toTop.classList.toggle("show", y > 320);

      if (els.header) {
        els.header.classList.toggle("compact", y > 40);

        if (y < 10) {
          els.header.classList.remove("headerHidden");
        } else if (delta > 8) {
          els.header.classList.add("headerHidden");
        } else if (delta < -8) {
          els.header.classList.remove("headerHidden");
        }
      }

      lastY = y;
      ticking = false;
    }

    window.addEventListener("scroll", () => {
      if (!ticking) {
        ticking = true;
        requestAnimationFrame(onScrollFrame);
      }
    }, { passive: true });

    // Go to Top (instant) + no focus on search
    els.toTop?.addEventListener("click", () => {
      window.scrollTo(0, 0);
      els.header?.classList.remove("headerHidden");
      document.activeElement?.blur?.();
    });
  }

  /* =======================
     Init
  ======================= */
  if (els.footerYear) els.footerYear.textContent = `© ${new Date().getFullYear()}`;

  initTabs();
  initCommandsEvents();
  initDorkBuilder();
  initPasswordTool();
  initCvssCalculator();
  initScrollUX();
  initHashTools();
  initCodecTools();
  loadCommands();
})();
