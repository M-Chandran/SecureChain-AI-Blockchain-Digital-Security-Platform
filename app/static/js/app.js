(function () {
    let booted = false;

    function bootApp() {
        if (booted) return;
        booted = true;

        const metaToken = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = metaToken ? metaToken.getAttribute("content") : "";

        const themeToggle = document.getElementById("theme-toggle");
        if (themeToggle) {
            themeToggle.addEventListener("click", function () {
                const html = document.documentElement;
                const darkEnabled = html.classList.toggle("dark");
                localStorage.setItem("theme", darkEnabled ? "dark" : "light");
            });
        }

        // Initialize by DOM presence, not page flags, to avoid script-order issues.
        initDashboardLiveUpdates(csrfToken);
        initUploadCheck(csrfToken);
        initAssistantChat(csrfToken);
        initPublicQrScan();
        initPasswordVisibilityToggles();
        initAuthLaneSwitches();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bootApp);
    } else {
        bootApp();
    }
})();

function initDashboardLiveUpdates(csrfToken) {
    const activityFeed = document.getElementById("activity-feed");
    const alertsFeed = document.getElementById("alerts-feed");
    const markReadButton = document.getElementById("mark-alerts-read");
    const statElements = document.querySelectorAll(".stat-value");
    const statCards = document.querySelectorAll(".stat-card");
    const statsGrid = document.getElementById("stats-grid");
    const scopedUserId = statsGrid ? (statsGrid.dataset.dashboardUser || "").trim() : "";
    const scopeQuery = scopedUserId ? `?user_id=${encodeURIComponent(scopedUserId)}` : "";
    if (!activityFeed || statElements.length === 0) {
        return;
    }

    // Track polling state to prevent flickering
    let isPolling = false;
    let pollInterval = null;

    if (markReadButton && alertsFeed) {
        markReadButton.addEventListener("click", async function () {
            try {
                const res = await fetch("/notifications/mark-read", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrfToken,
                    },
                    body: JSON.stringify({}),
                });
                if (res.ok) {
                    Array.from(alertsFeed.children).forEach((item) => {
                        item.classList.add("opacity-70");
                    });
                }
            } catch (_err) {
                // keep silent
            }
        });
    }

    const update = async () => {
        // Prevent concurrent polling to avoid flickering
        if (isPolling) return;
        isPolling = true;

        try {
            // Check session validity first by checking stats endpoint
            const statsRes = await fetch(`/api/stats${scopeQuery}`, {
                credentials: 'same-origin'
            });

            // If unauthorized or redirect, stop polling and reload to login
            if (statsRes.status === 401 || statsRes.status === 302 || !statsRes.ok) {
                // Session expired or invalid - stop polling and let user re-authenticate
                if (pollInterval) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                }
                // Don't reload immediately - let the user see the current state
                // The server-side guards will handle redirect to login
                return;
            }

            const statsJson = await statsRes.json();
            statElements.forEach((el) => {
                const key = el.dataset.key;
                if (!key || statsJson.analytics[key] === undefined) return;
                const val = statsJson.analytics[key];
                el.textContent = key === "protection_score" ? `${val}%` : String(val);
            });
            statCards.forEach((card) => card.classList.remove("skeleton"));

            const activityRes = await fetch(`/api/activities${scopeQuery}`, {
                credentials: 'same-origin'
            });
            if (activityRes.ok) {
                const activityJson = await activityRes.json();
                renderActivityFeed(activityFeed, activityJson.activities || []);
            }

            if (alertsFeed) {
                const alertsRes = await fetch(`/api/notifications${scopeQuery}`, {
                    credentials: 'same-origin'
                });
                if (alertsRes.ok) {
                    const alertsJson = await alertsRes.json();
                    renderAlertsFeed(alertsFeed, alertsJson.alerts || []);
                }
            }
        } catch (_err) {
            // Silent failure keeps UI stable when polling fails due to network issues
            // Don't stop polling on network errors - just skip this update cycle
        } finally {
            isPolling = false;
        }
    };

    // Initial update
    update();

    // Start polling with longer interval to reduce flickering
    // and only poll when page is visible
    const startPolling = () => {
        if (!pollInterval) {
            pollInterval = setInterval(update, 15000); // 15 seconds instead of 12
        }
    };

    // Handle page visibility to pause/resume polling
    if (typeof document.hidden !== 'undefined') {
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                if (pollInterval) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                }
            } else {
                // Refresh data when page becomes visible again
                update();
                startPolling();
            }
        });
    }

    startPolling();
}

function initUploadCheck(csrfToken) {
    const fileInput = document.getElementById("multi-upload-input");
    const checkButton = document.getElementById("upload-check-button");
    const output = document.getElementById("upload-check-results");
    if (!fileInput || !checkButton || !output) {
        return;
    }

    const showMessage = (html) => {
        output.classList.remove("hidden");
        output.innerHTML = html;
    };

    checkButton.addEventListener("click", async function () {
        const files = fileInput.files ? Array.from(fileInput.files) : [];
        if (!files.length) {
            showMessage('<p class="text-amber-200">Select one or more files first.</p>');
            return;
        }

        const formData = new FormData();
        files.forEach((file) => formData.append("document", file));

        showMessage('<p class="text-cyan-200">Running upload checks...</p>');

        try {
            const response = await fetch("/api/upload/check", {
                method: "POST",
                headers: {
                    "X-CSRF-Token": csrfToken,
                },
                body: formData,
            });
            const data = await response.json();
            if (!response.ok || data.status === "error") {
                showMessage(`<p class="text-rose-200">${escapeHtml(data.message || "Upload check failed.")}</p>`);
                return;
            }

            const rows = Array.isArray(data.checks) ? data.checks : [];
            const summary = data.summary || {};
            const summaryHtml = `
                <p class="mb-2 text-cyan-200">
                    Checked ${escapeHtml(String(summary.total || 0))} file(s):
                    accepted ${escapeHtml(String(summary.accepted || 0))},
                    blocked ${escapeHtml(String(summary.blocked || 0))}.
                </p>
            `;
            const tableHtml = rows.length
                ? `
                <div class="overflow-x-auto">
                    <table class="min-w-full text-left text-[11px] text-slate-300">
                        <thead class="text-slate-400">
                            <tr>
                                <th class="px-2 py-1">File</th>
                                <th class="px-2 py-1">Size</th>
                                <th class="px-2 py-1">Type</th>
                                <th class="px-2 py-1">Risk</th>
                                <th class="px-2 py-1">Result</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows
                                .map((row) => {
                                    const accepted = !!row.accepted;
                                    const duplicate = !!row.duplicate;
                                    const result = accepted
                                        ? `Accept (${escapeHtml(row.suggested_status || "active")})`
                                        : duplicate
                                        ? `Duplicate of ${escapeHtml(row.duplicate_verification_id || row.duplicate_drive_id || "existing")}`
                                        : "Blocked by policy";
                                    const resultColor = accepted ? "text-emerald-300" : "text-rose-300";
                                    return `
                                        <tr class="border-t border-slate-700/40">
                                            <td class="px-2 py-1">${escapeHtml(row.filename || "")}</td>
                                            <td class="px-2 py-1">${escapeHtml(String(row.size_mb || 0))} MB</td>
                                            <td class="px-2 py-1">${escapeHtml(row.mime_type || "-")}</td>
                                            <td class="px-2 py-1">${escapeHtml(String(row.quick_risk || 0))}%</td>
                                            <td class="px-2 py-1 ${resultColor}">${result}</td>
                                        </tr>
                                    `;
                                })
                                .join("")}
                        </tbody>
                    </table>
                </div>
            `
                : '<p class="text-slate-400">No file checks available.</p>';

            showMessage(summaryHtml + tableHtml);
        } catch (_err) {
            showMessage('<p class="text-rose-200">Upload check failed. Try again.</p>');
        }
    });
}

function initPasswordVisibilityToggles() {
    const toggleButtons = document.querySelectorAll("[data-password-toggle]");
    if (!toggleButtons.length) {
        return;
    }

    toggleButtons.forEach((button) => {
        const targetId = button.getAttribute("data-target") || "";
        if (!targetId) {
            return;
        }
        const input = document.getElementById(targetId);
        if (!input) {
            return;
        }
        const label = button.querySelector("[data-toggle-label]");

        const setVisible = (isVisible) => {
            input.type = isVisible ? "text" : "password";
            button.setAttribute("aria-pressed", isVisible ? "true" : "false");
            if (label) {
                label.textContent = isVisible ? "Hide" : "Show";
            } else {
                button.textContent = isVisible ? "Hide" : "Show";
            }
        };

        setVisible(false);
        button.addEventListener("click", function () {
            setVisible(input.type === "password");
            try {
                input.focus({ preventScroll: true });
            } catch (_err) {
                input.focus();
            }
        });
    });
}

function initAuthLaneSwitches() {
    const roots = document.querySelectorAll("[data-lane-root]");
    if (!roots.length) {
        return;
    }

    roots.forEach((root) => {
        const buttons = root.querySelectorAll("[data-lane-btn]");
        const panels = root.querySelectorAll("[data-lane-panel]");
        if (!buttons.length || !panels.length) {
            return;
        }

        const setLane = (lane) => {
            buttons.forEach((button) => {
                const isActive = (button.getAttribute("data-lane-btn") || "") === lane;
                button.classList.toggle("is-active", isActive);
                button.setAttribute("aria-pressed", isActive ? "true" : "false");
            });

            panels.forEach((panel) => {
                const isActive = (panel.getAttribute("data-lane-panel") || "") === lane;
                panel.hidden = !isActive;
            });
        };

        const first = buttons[0].getAttribute("data-lane-btn") || "";
        const initial =
            Array.from(buttons).find((button) => button.classList.contains("is-active"))?.getAttribute("data-lane-btn") ||
            first;

        if (initial) {
            setLane(initial);
        }

        buttons.forEach((button) => {
            button.addEventListener("click", function () {
                const lane = button.getAttribute("data-lane-btn") || "";
                if (!lane) {
                    return;
                }
                setLane(lane);
            });
        });
    });
}

function renderActivityFeed(container, activities) {
    if (!activities.length) {
        container.innerHTML = '<li class="rounded-xl border border-slate-700/40 bg-slate-900/40 p-3 text-slate-400">No activity logs yet.</li>';
        return;
    }
    container.innerHTML = activities
        .map((item) => {
            const timestamp = (item.timestamp || "").slice(0, 19);
            return `
                <li class="rounded-xl border border-slate-700/40 bg-slate-900/40 p-3">
                    <p class="font-mono text-slate-300">${escapeHtml(timestamp)} UTC</p>
                    <p class="mt-1 text-cyan-200">${escapeHtml(item.action || "")} <span class="text-slate-400">(${escapeHtml(item.status || "")})</span></p>
                    <p class="text-slate-400">${escapeHtml(item.details || "")}</p>
                </li>
            `;
        })
        .join("");
}

function renderAlertsFeed(container, alerts) {
    if (!alerts.length) {
        container.innerHTML = '<li class="rounded-lg border border-slate-700/40 bg-slate-900/40 p-2 text-slate-400">No alerts.</li>';
        return;
    }
    container.innerHTML = alerts
        .map((alert) => {
            const badgeColor =
                alert.severity === "critical"
                    ? "text-rose-300"
                    : alert.severity === "warning"
                    ? "text-amber-300"
                    : "text-cyan-200";
            return `
                <li class="rounded-lg border border-slate-700/40 bg-slate-900/40 p-2 ${alert.is_read === "1" ? "opacity-70" : ""}">
                    <p class="text-slate-300">${escapeHtml(alert.title || "")} <span class="${badgeColor}">(${escapeHtml(alert.severity || "info")})</span></p>
                    <p class="text-slate-400">${escapeHtml(alert.message || "")}</p>
                </li>
            `;
        })
        .join("");
}

function initAssistantChat(csrfToken) {
    const form = document.getElementById("chat-form");
    const messageInput = document.getElementById("message-input");
    const verificationIdSelect = document.getElementById("verification-id");
    const chatBox = document.getElementById("chat-box");
    if (!form || !messageInput || !chatBox) {
        return;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        const message = messageInput.value.trim();
        if (!message) return;

        appendChatBubble(chatBox, message, "user");
        messageInput.value = "";

        const loadingBubble = appendChatBubble(chatBox, "Analyzing...", "assistant");
        try {
            const response = await fetch("/api/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken,
                },
                body: JSON.stringify({
                    message,
                    verification_id: verificationIdSelect ? verificationIdSelect.value : "",
                }),
            });
            const data = await response.json();
            if (!response.ok || data.status === "error") {
                loadingBubble.textContent = "Assistant unavailable right now. Try again.";
                return;
            }

            const tips = Array.isArray(data.tips) ? data.tips : [];
            loadingBubble.innerHTML = `
                <p>${escapeHtml(data.reply || "")}</p>
                ${
                    tips.length
                        ? `<ul class="mt-2 list-disc pl-4">${tips
                              .map((t) => `<li>${escapeHtml(t)}</li>`)
                              .join("")}</ul>`
                        : ""
                }
            `;
        } catch (_err) {
            loadingBubble.textContent = "Assistant unavailable right now. Try again.";
        }
        chatBox.scrollTop = chatBox.scrollHeight;
    });
}

function initSupportWidget(csrfToken) {
    const toggle = document.getElementById("support-widget-toggle");
    const panel = document.getElementById("support-widget-panel");
    const closeBtn = document.getElementById("support-widget-close");
    const form = document.getElementById("support-widget-form");
    const input = document.getElementById("support-widget-input");
    const messages = document.getElementById("support-widget-messages");
    if (!toggle || !panel || !form || !input || !messages) {
        return;
    }

    toggle.addEventListener("click", function () {
        panel.classList.toggle("hidden");
    });
    if (closeBtn) {
        closeBtn.addEventListener("click", function () {
            panel.classList.add("hidden");
        });
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        const message = input.value.trim();
        if (!message) return;
        appendSupportMessage(messages, message, "user");
        input.value = "";
        const pending = appendSupportMessage(messages, "Thinking...", "assistant");

        try {
            const response = await fetch("/api/support-chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken,
                },
                body: JSON.stringify({ message }),
            });
            const data = await response.json();
            if (!response.ok || data.status === "error") {
                pending.textContent = "Support bot is temporarily unavailable.";
                return;
            }
            const steps = Array.isArray(data.steps) ? data.steps : [];
            pending.innerHTML = `
                <p>${escapeHtml(data.reply || "")}</p>
                ${
                    steps.length
                        ? `<ul class="mt-2 list-disc pl-4">${steps
                              .map((s) => `<li>${escapeHtml(s)}</li>`)
                              .join("")}</ul>`
                        : ""
                }
            `;
        } catch (_err) {
            pending.textContent = "Support bot is temporarily unavailable.";
        }
        messages.scrollTop = messages.scrollHeight;
    });
}

function initSupportPageChat(csrfToken) {
    const form = document.getElementById("support-chat-form");
    const input = document.getElementById("support-message-input");
    const box = document.getElementById("support-chat-box");
    if (!form || !input || !box) {
        return;
    }
    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        const message = input.value.trim();
        if (!message) return;
        appendSupportMessage(box, message, "user");
        input.value = "";
        const pending = appendSupportMessage(box, "Thinking...", "assistant");
        try {
            const response = await fetch("/api/support-chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken,
                },
                body: JSON.stringify({ message }),
            });
            const data = await response.json();
            if (!response.ok || data.status === "error") {
                pending.textContent = "Support bot is unavailable.";
                return;
            }
            const steps = Array.isArray(data.steps) ? data.steps : [];
            pending.innerHTML = `
                <p>${escapeHtml(data.reply || "")}</p>
                ${
                    steps.length
                        ? `<ul class="mt-2 list-disc pl-4">${steps
                              .map((s) => `<li>${escapeHtml(s)}</li>`)
                              .join("")}</ul>`
                        : ""
                }
            `;
        } catch (_err) {
            pending.textContent = "Support bot is unavailable.";
        }
        box.scrollTop = box.scrollHeight;
    });
}

function appendChatBubble(chatBox, text, role) {
    const bubble = document.createElement("div");
    bubble.className =
        role === "user"
            ? "ml-auto max-w-[85%] rounded-xl border border-cyan-400/30 bg-cyan-500/10 p-3 text-sm text-cyan-100"
            : "max-w-[85%] rounded-xl border border-violet-400/30 bg-violet-500/10 p-3 text-sm text-violet-100";
    bubble.textContent = text;
    chatBox.appendChild(bubble);
    chatBox.scrollTop = chatBox.scrollHeight;
    return bubble;
}

function appendSupportMessage(container, text, role) {
    const bubble = document.createElement("div");
    bubble.className =
        role === "user"
            ? "ml-auto max-w-[85%] rounded-lg border border-cyan-400/30 bg-cyan-500/10 p-2 text-xs text-cyan-100"
            : "max-w-[85%] rounded-lg border border-violet-400/30 bg-violet-500/10 p-2 text-xs text-violet-100";
    bubble.textContent = text;
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
    return bubble;
}

function initPublicQrScan() {
    const startBtn = document.getElementById("start-qr");
    const stopBtn = document.getElementById("stop-qr");
    const wrap = document.getElementById("qr-reader-wrap");
    const input = document.querySelector('input[name="verification_id"]');
    const form = input ? input.closest("form") : null;
    if (!startBtn || !wrap || !input || !form) {
        return;
    }

    let scanner = null;
    const stopScanner = async () => {
        if (!scanner) return;
        try {
            await scanner.stop();
            await scanner.clear();
        } catch (_err) {
            // ignore stop failures
        }
        scanner = null;
    };

    startBtn.addEventListener("click", async function () {
        if (typeof Html5Qrcode === "undefined") return;
        wrap.classList.remove("hidden");
        scanner = new Html5Qrcode("qr-reader");
        try {
            await scanner.start(
                { facingMode: "environment" },
                { fps: 10, qrbox: 220 },
                async (decodedText) => {
                    const vid = extractVerificationId(decodedText);
                    if (vid) {
                        input.value = vid;
                        await stopScanner();
                        form.submit();
                    }
                }
            );
        } catch (_err) {
            // camera denied / unavailable
        }
    });

    if (stopBtn) {
        stopBtn.addEventListener("click", async function () {
            await stopScanner();
            wrap.classList.add("hidden");
        });
    }
}

function extractVerificationId(decodedText) {
    const value = (decodedText || "").trim();
    if (!value) return "";
    try {
        const parsed = new URL(value);
        const fromQuery = parsed.searchParams.get("verification_id");
        if (fromQuery) return fromQuery.toUpperCase();
    } catch (_err) {
        // not URL format
    }
    const match = value.match(/[A-Za-z0-9]{10,16}/);
    return match ? match[0].toUpperCase() : "";
}

function escapeHtml(input) {
    return String(input)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
