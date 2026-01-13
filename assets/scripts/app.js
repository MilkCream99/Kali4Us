/* Kali4Us app.js
   - Header hides on scroll down, shows on scroll up
   - Go to Top button appears after scrolling
   - Go to Top scroll is INSTANT (not smooth)
   - No bottom sheet, no pin
   - Search + chips + copy + toast
*/

(() => {
  "use strict";

  const els = {
    header: document.getElementById("siteHeader"),
    q: document.getElementById("q"),
    clear: document.getElementById("clear"),
    chips: document.getElementById("chips"),
    results: document.getElementById("results"),
    count: document.getElementById("count"),
    filterHint: document.getElementById("filterHint"),
    toast: document.getElementById("toast"),
    footerYear: document.getElementById("footerYear"),
    linkAbout: document.getElementById("linkAbout"),
    linkSource: document.getElementById("linkSource"),
    linkContact: document.getElementById("linkContact"),
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
    els.toast.textContent = msg;
    els.toast.classList.add("show");
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => els.toast.classList.remove("show"), 1600);
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

  function uniqueCategories(items) {
    const set = new Set();
    for (const it of items) if (it?.category) set.add(String(it.category));
    return ["All", ...Array.from(set).sort((a,b)=>a.localeCompare(b))];
  }

  function renderChips(categories) {
    els.chips.innerHTML = "";
    for (const cat of categories) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chip";
      btn.textContent = cat;
      btn.setAttribute("aria-pressed", String(cat === activeCategory));
      btn.addEventListener("click", () => {
        activeCategory = cat;
        update();
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
    const tokens = tokenize(els.q.value);
    return ALL.filter((it) => {
      if (activeCategory !== "All" && String(it.category) !== activeCategory) return false;
      return matchesQuery(it, tokens);
    });
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

  function render(items) {
    const tokens = tokenize(els.q.value);

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

      article.querySelector("button").addEventListener("click", () => copyText(it.cmd));
      els.results.appendChild(article);
    }
  }

  function updateMeta(visibleCount, totalCount) {
    els.count.textContent = `${visibleCount} / ${totalCount} commands`;

    const q = normalize(els.q.value);
    const parts = [];
    if (activeCategory !== "All") parts.push(`Category: ${activeCategory}`);
    if (q) parts.push(`Query: "${els.q.value.trim()}"`);
    els.filterHint.textContent = parts.length ? parts.join(" • ") : "Showing all";
  }

  function update() {
    const filtered = filterItems();
    render(filtered);
    updateMeta(filtered.length, ALL.length);
    els.clear.classList.toggle("show", !!normalize(els.q.value));
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
    update();
  }

  // Footer year
  if (els.footerYear) els.footerYear.textContent = `© ${new Date().getFullYear()}`;

  // Footer links (optional toast)
  function wireFooterLink(el, label) {
    if (!el) return;
    el.addEventListener("click", (e) => {
      const href = (el.getAttribute("href") || "").trim();
      if (href === "#" || href === "") {
        e.preventDefault();
        showToast(`${label} (set your link)`);
      }
    });
  }
  wireFooterLink(els.linkAbout, "About");
  wireFooterLink(els.linkSource, "Source");
  wireFooterLink(els.linkContact, "Contact");

  // Search events
  els.q.addEventListener("input", update);
  els.clear.addEventListener("click", () => {
    els.q.value = "";
    update();
    els.q.focus();
  });

  // ===== Scroll behavior: header hide/show + go-to-top =====
  let lastY = window.scrollY || 0;
  let ticking = false;

  function onScrollFrame() {
    const y = window.scrollY || 0;
    const delta = y - lastY;

    // show Go to Top after 320px
    if (els.toTop) els.toTop.classList.toggle("show", y > 320);

    // header show/hide (ignore tiny moves)
    if (els.header) {
      if (y < 10) {
        els.header.classList.remove("headerHidden");
      } else if (delta > 8) {
        els.header.classList.add("headerHidden"); // down
      } else if (delta < -8) {
        els.header.classList.remove("headerHidden"); // up
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

  // ✅ Go to Top click (INSTANT, NOT SMOOTH)
  // ✅ Go to Top click (INSTANT) + NO focus on search
if (els.toTop) {
  els.toTop.addEventListener("click", () => {
    window.scrollTo(0, 0); // instant jump

    // show header again (optional)
    els.header?.classList.remove("headerHidden");

    // remove focus from anything (so cursor won't appear)
    document.activeElement?.blur?.();
  });
}


  // Init
  loadCommands();
})();
