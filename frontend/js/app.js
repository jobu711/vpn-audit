/**
 * VPN Privacy Audit Suite - Dashboard Application
 *
 * Handles WebSocket connection for live monitoring and
 * REST API calls for audit test execution.
 */

(function () {
  "use strict";

  // ---- Configuration ----

  const WS_RECONNECT_DELAY_MS = 3000;
  const WS_MAX_RECONNECT_DELAY_MS = 30000;
  const MAX_EVENT_LOG_ENTRIES = 50;
  const LATENCY_MAX_MS = 200; // Gauge ceiling for latency ring
  const BANDWIDTH_MAX_MBPS = 200; // Gauge ceiling for bandwidth ring

  // ---- DOM References ----

  const dom = {
    // Connection badge
    connectionBadge: document.getElementById("connectionBadge"),
    badgeText: document.querySelector(".badge-text"),
    wsIndicator: document.getElementById("wsIndicator"),

    // Gauges
    latencyValue: document.getElementById("latencyValue"),
    latencyFill: document.getElementById("latencyFill"),
    bandwidthValue: document.getElementById("bandwidthValue"),
    bandwidthFill: document.getElementById("bandwidthFill"),

    // Monitor sections
    interfaceList: document.getElementById("interfaceList"),
    routeList: document.getElementById("routeList"),
    eventLog: document.getElementById("eventLog"),
    lastUpdate: document.getElementById("lastUpdate"),

    // Audit results
    resultLeaks: document.getElementById("result-leaks"),
    resultFingerprint: document.getElementById("result-fingerprint"),
    resultKillswitch: document.getElementById("result-killswitch"),
    resultFull: document.getElementById("result-full"),

    // External IP
    extipAddress: document.getElementById("extipAddress"),
    extipLocation: document.getElementById("extipLocation"),
    extipIsp: document.getElementById("extipIsp"),
    extipBadge: document.getElementById("extipBadge"),

    // Buttons
    btnFetchResults: document.getElementById("btnFetchResults"),
  };

  // ---- WebSocket ----

  let ws = null;
  let wsReconnectDelay = WS_RECONNECT_DELAY_MS;
  let wsReconnectTimer = null;

  function connectWebSocket() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/monitor`;

    ws = new WebSocket(url);

    ws.onopen = function () {
      wsReconnectDelay = WS_RECONNECT_DELAY_MS;
      setConnectionStatus("connected");
    };

    ws.onmessage = function (event) {
      try {
        var data = JSON.parse(event.data);
        handleMonitorUpdate(data);
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    ws.onclose = function () {
      setConnectionStatus("disconnected");
      scheduleReconnect();
    };

    ws.onerror = function () {
      setConnectionStatus("disconnected");
      // onclose will fire after onerror
    };
  }

  function scheduleReconnect() {
    if (wsReconnectTimer) return;
    wsReconnectTimer = setTimeout(function () {
      wsReconnectTimer = null;
      connectWebSocket();
      // Exponential backoff capped at max
      wsReconnectDelay = Math.min(wsReconnectDelay * 1.5, WS_MAX_RECONNECT_DELAY_MS);
    }, wsReconnectDelay);
  }

  function setConnectionStatus(status) {
    var badge = dom.connectionBadge;
    var indicator = dom.wsIndicator;

    badge.classList.remove("connected", "disconnected");
    indicator.classList.remove("connected", "disconnected");

    if (status === "connected") {
      badge.classList.add("connected");
      indicator.classList.add("connected");
      dom.badgeText.textContent = "Connected";
    } else {
      badge.classList.add("disconnected");
      indicator.classList.add("disconnected");
      dom.badgeText.textContent = "Disconnected";
    }
  }

  // ---- Monitor Update Handler ----

  function handleMonitorUpdate(data) {
    updateExternalIP(data.external_ip);
    updateGauges(data);
    updateInterfaces(data.interfaces || [], data.bandwidth_per_interface || {});
    updateRoutes(data.routing || []);
    updateEventLog(data.event || null, data.timestamp);
    dom.lastUpdate.textContent = formatTimestamp(data.timestamp);
  }

  // ---- External IP ----

  function updateExternalIP(info) {
    if (!info || info.status === "error") {
      dom.extipAddress.textContent = "Unavailable";
      dom.extipLocation.textContent = "--";
      dom.extipIsp.textContent = "--";
      dom.extipBadge.textContent = "Unknown";
      dom.extipBadge.className = "extip-badge unknown";
      return;
    }

    dom.extipAddress.textContent = info.ip || "--";

    var parts = [];
    if (info.city) parts.push(info.city);
    if (info.country) parts.push(info.country);
    dom.extipLocation.textContent = parts.length ? parts.join(", ") : "--";

    dom.extipIsp.textContent = info.isp || "--";

    if (info.vpn_masked === true) {
      dom.extipBadge.textContent = "Masked";
      dom.extipBadge.className = "extip-badge masked";
    } else if (info.vpn_masked === false) {
      dom.extipBadge.textContent = "Exposed";
      dom.extipBadge.className = "extip-badge exposed";
    } else {
      dom.extipBadge.textContent = "Unknown";
      dom.extipBadge.className = "extip-badge unknown";
    }
  }

  // ---- Gauges ----

  /**
   * The SVG circle has radius 50, so circumference = 2 * PI * 50 = ~314.16.
   * stroke-dasharray is set to 314 in CSS.
   * stroke-dashoffset of 314 = empty, 0 = full.
   */
  var CIRCUMFERENCE = 314;

  function updateGauges(data) {
    // Latency
    var latency = data.latency_ms;
    if (latency != null) {
      dom.latencyValue.textContent = latency < 1 ? "<1" : Math.round(latency);
      var latencyRatio = Math.min(latency / LATENCY_MAX_MS, 1);
      dom.latencyFill.style.strokeDashoffset = CIRCUMFERENCE * (1 - latencyRatio);

      // Color code: green < 50ms, yellow < 100ms, red >= 100ms
      if (latency < 50) {
        dom.latencyFill.style.stroke = "#4caf50";
      } else if (latency < 100) {
        dom.latencyFill.style.stroke = "#ff9800";
      } else {
        dom.latencyFill.style.stroke = "#f44336";
      }
    } else {
      dom.latencyValue.textContent = "--";
      dom.latencyFill.style.strokeDashoffset = CIRCUMFERENCE;
    }

    // Bandwidth
    var bandwidth = data.bandwidth_mbps;
    if (bandwidth != null) {
      dom.bandwidthValue.textContent = bandwidth < 0.1 ? "<0.1" : bandwidth.toFixed(1);
      var bwRatio = Math.min(bandwidth / BANDWIDTH_MAX_MBPS, 1);
      dom.bandwidthFill.style.strokeDashoffset = CIRCUMFERENCE * (1 - bwRatio);
    } else {
      dom.bandwidthValue.textContent = "--";
      dom.bandwidthFill.style.strokeDashoffset = CIRCUMFERENCE;
    }
  }

  // ---- Interfaces ----

  var TUNNEL_PREFIXES = ["tun", "wg", "proton", "nordlynx", "mullvad", "utun", "ppp"];

  function isTunnelInterface(name) {
    var lower = name.toLowerCase();
    for (var i = 0; i < TUNNEL_PREFIXES.length; i++) {
      if (lower.indexOf(TUNNEL_PREFIXES[i]) === 0) return true;
    }
    return false;
  }

  function updateInterfaces(interfaces, bandwidthPerInterface) {
    if (!interfaces.length) {
      dom.interfaceList.innerHTML = '<div class="placeholder-text">No interfaces detected</div>';
      return;
    }

    var html = "";
    for (var i = 0; i < interfaces.length; i++) {
      var iface = interfaces[i];
      var statusCls = iface.is_up ? "up" : "down";
      var addrs = iface.addresses && iface.addresses.length
        ? iface.addresses.join(", ")
        : "No address";

      var bwHtml = "";
      if (bandwidthPerInterface && bandwidthPerInterface[iface.name] != null) {
        var bw = bandwidthPerInterface[iface.name];
        var isTunnel = isTunnelInterface(iface.name);
        var bwCls = "iface-bandwidth";
        if (!isTunnel && bw > 0.1) {
          bwCls += " iface-bandwidth-warning";
        } else {
          bwCls += " iface-bandwidth-ok";
        }
        bwHtml = '<span class="' + bwCls + '">' + bw.toFixed(1) + ' Mbps</span>';
      }

      html +=
        '<div class="interface-item">' +
          '<span class="iface-status ' + statusCls + '"></span>' +
          '<span class="iface-name">' + escapeHtml(iface.name) + '</span>' +
          '<span class="iface-addrs">' + escapeHtml(addrs) + '</span>' +
          bwHtml +
        '</div>';
    }

    dom.interfaceList.innerHTML = html;
  }

  // ---- Routes ----

  function updateRoutes(routes) {
    if (!routes.length) {
      dom.routeList.innerHTML = '<div class="placeholder-text">No routes available</div>';
      return;
    }

    // Show at most 15 routes to avoid overwhelming the UI
    var displayed = routes.slice(0, 15);
    var html = "";

    for (var i = 0; i < displayed.length; i++) {
      var r = displayed[i];
      var gw = r.gateway || r.via || "-";
      var iface = r.interface || r.dev || "-";

      html +=
        '<div class="route-item">' +
          '<span class="route-dest">' + escapeHtml(r.destination || "-") + '</span>' +
          '<span class="route-gw">' + escapeHtml(gw) + '</span>' +
          '<span class="route-iface">' + escapeHtml(iface) + '</span>' +
        '</div>';
    }

    if (routes.length > 15) {
      html += '<div class="placeholder-text">+ ' + (routes.length - 15) + ' more routes</div>';
    }

    dom.routeList.innerHTML = html;
  }

  // ---- Event Log ----

  function updateEventLog(event, timestamp) {
    if (!event) return;

    // Remove placeholder if present
    var placeholder = dom.eventLog.querySelector(".placeholder-text");
    if (placeholder) {
      placeholder.remove();
    }

    var entry = document.createElement("div");
    entry.className = "event-entry";

    var time = formatTime(timestamp);
    var msg = "";

    if (event.type === "initial") {
      entry.classList.add("event-initial");
      msg = time + " Connection initialized";
    } else if (event.type === "change") {
      entry.classList.add("event-change");
      var parts = [];
      if (event.interfaces_added) {
        parts.push("IF added: " + event.interfaces_added.join(", "));
      }
      if (event.interfaces_removed) {
        parts.push("IF removed: " + event.interfaces_removed.join(", "));
      }
      if (event.interfaces_status_changed) {
        parts.push("IF status: " + event.interfaces_status_changed.join(", "));
      }
      if (event.routing_changed) {
        parts.push("Routing table changed");
      }
      msg = time + " " + (parts.length ? parts.join(" | ") : "State change detected");
    } else {
      msg = time + " " + JSON.stringify(event);
    }

    entry.textContent = msg;

    // Prepend newest at top
    dom.eventLog.insertBefore(entry, dom.eventLog.firstChild);

    // Limit entries
    while (dom.eventLog.children.length > MAX_EVENT_LOG_ENTRIES) {
      dom.eventLog.removeChild(dom.eventLog.lastChild);
    }
  }

  // ---- Audit Controls ----

  function bindAuditButtons() {
    var buttons = document.querySelectorAll(".btn-run");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", onAuditButtonClick);
    }

    dom.btnFetchResults.addEventListener("click", fetchStoredResults);
  }

  function onAuditButtonClick(e) {
    var btn = e.currentTarget;
    var endpoint = btn.getAttribute("data-endpoint");
    var target = btn.getAttribute("data-target");

    if (btn.classList.contains("loading")) return;

    runAudit(btn, endpoint, target);
  }

  function runAudit(btn, endpoint, target) {
    btn.classList.add("loading");
    btn.disabled = true;

    var resultEl = document.getElementById("result-" + target);
    resultEl.className = "card-result";
    resultEl.innerHTML = '<div class="result-placeholder">Running audit...</div>';

    fetch(endpoint, { method: "POST" })
      .then(function (response) {
        if (!response.ok) {
          return response.json().then(function (data) {
            throw new Error(data.error || "Request failed with status " + response.status);
          });
        }
        return response.json();
      })
      .then(function (data) {
        if (target === "full") {
          renderFullResult(resultEl, data);
        } else {
          renderSingleResult(resultEl, data, target);
        }
      })
      .catch(function (err) {
        resultEl.className = "card-result status-fail";
        resultEl.innerHTML = '<div class="error-result">Error: ' + escapeHtml(err.message) + '</div>';
      })
      .finally(function () {
        btn.classList.remove("loading");
        btn.disabled = false;
      });
  }

  function renderSingleResult(el, data, auditType) {
    if (auditType === "leaks") return renderLeakResult(el, data);
    if (auditType === "fingerprint") return renderFingerprintResult(el, data);
    if (auditType === "killswitch") return renderKillswitchResult(el, data);

    // Fallback: existing status + JSON details display
    var status = data.status || "warning";
    el.className = "card-result status-" + status;

    var icon = statusIcon(status);
    var label = status.toUpperCase();

    var detailsStr = "";
    if (data.details && typeof data.details === "object") {
      detailsStr = JSON.stringify(data.details, null, 2);
    }

    var html =
      '<div class="result-status ' + status + '">' +
        '<span class="status-icon">' + icon + '</span>' +
        '<span>' + label + '</span>' +
      '</div>';

    if (detailsStr) {
      html += '<div class="result-details">' + escapeHtml(detailsStr) + '</div>';
    }

    if (data.timestamp) {
      html += '<div class="result-timestamp">' + formatTimestamp(data.timestamp) + '</div>';
    }

    el.innerHTML = html;
  }

  // ---- Module-Specific Renderers ----

  function renderLeakResult(el, data) {
    var status = data.status || "warning";
    el.className = "card-result status-" + status;

    var details = data.details || {};
    var checks = [
      { name: "DNS", key: "dns", itemsKey: "servers" },
      { name: "WebRTC", key: "webrtc", itemsKey: "ips" },
      { name: "IPv6", key: "ipv6", itemsKey: "addresses" }
    ];

    var html =
      '<div class="result-status ' + status + '">' +
        '<span class="status-icon">' + statusIcon(status) + '</span>' +
        '<span>' + status.toUpperCase() + '</span>' +
      '</div>' +
      '<table class="result-table">' +
        '<thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead>' +
        '<tbody>';

    for (var i = 0; i < checks.length; i++) {
      var c = checks[i];
      var info = details[c.key] || {};
      var leaked = info.leaked;
      var badgeCls = leaked ? "fail" : "pass";
      var badgeLabel = leaked ? "FAIL" : "PASS";
      var items = info[c.itemsKey] || [];
      var detailText = "";

      if (leaked && items.length) {
        detailText = '<span class="leak-detail">' + escapeHtml(items.join(", ")) + '</span>';
      } else if (!leaked) {
        detailText = '<span class="leak-detail">None detected</span>';
      }

      html +=
        '<tr>' +
          '<td>' + c.name + '</td>' +
          '<td><span class="status-badge ' + badgeCls + '">' + badgeLabel + '</span></td>' +
          '<td>' + detailText + '</td>' +
        '</tr>';
    }

    html += '</tbody></table>';

    if (data.timestamp) {
      html += '<div class="result-timestamp">' + formatTimestamp(data.timestamp) + '</div>';
    }

    el.innerHTML = html;
  }

  function renderFingerprintResult(el, data) {
    var status = data.status || "warning";
    el.className = "card-result status-" + status;

    var details = data.details || {};
    var protocols = details.protocols || {};
    var totalPackets = details.total_packets || 0;
    var vpnRatio = details.vpn_ratio;
    var reason = details.reason || "";

    // Determine protocol names and sort by packet count descending
    var protoNames = [];
    for (var key in protocols) {
      if (protocols.hasOwnProperty(key)) {
        protoNames.push(key);
      }
    }
    protoNames.sort(function (a, b) { return protocols[b] - protocols[a]; });

    var html =
      '<div class="result-status ' + status + '">' +
        '<span class="status-icon">' + statusIcon(status) + '</span>' +
        '<span>' + status.toUpperCase() + '</span>' +
      '</div>' +
      '<table class="result-table">' +
        '<thead><tr><th>Protocol</th><th>Packets</th><th>Distribution</th></tr></thead>' +
        '<tbody>';

    for (var i = 0; i < protoNames.length; i++) {
      var name = protoNames[i];
      var count = protocols[name];
      var pct = totalPackets > 0 ? (count / totalPackets * 100) : 0;

      html +=
        '<tr>' +
          '<td>' + escapeHtml(name) + '</td>' +
          '<td>' + count + '</td>' +
          '<td>' +
            '<div class="protocol-bar">' +
              '<div class="protocol-bar-fill" style="width: ' + pct.toFixed(1) + '%"></div>' +
            '</div>' +
          '</td>' +
        '</tr>';
    }

    html += '</tbody></table>';

    // VPN exposure ratio
    if (vpnRatio != null) {
      var ratioPct = (vpnRatio * 100).toFixed(1);
      var ratioColor = "";
      if (vpnRatio < 0.03) {
        ratioColor = "pass";
      } else if (vpnRatio < 0.10) {
        ratioColor = "warning";
      } else {
        ratioColor = "fail";
      }
      html +=
        '<div class="ks-summary">' +
          '<span>VPN exposure ratio: </span>' +
          '<span class="status-badge ' + ratioColor + '">' + ratioPct + '%</span>' +
        '</div>';
    }

    if (reason) {
      html += '<div class="ks-summary">' + escapeHtml(reason) + '</div>';
    }

    if (data.timestamp) {
      html += '<div class="result-timestamp">' + formatTimestamp(data.timestamp) + '</div>';
    }

    el.innerHTML = html;
  }

  function renderKillswitchResult(el, data) {
    var status = data.status || "warning";
    el.className = "card-result status-" + status;

    var details = data.details || {};
    var duration = details.duration;
    var totalPkts = details.total_packets;
    var tunnelPkts = details.tunnel_packets;
    var leakedPkts = details.leaked_packets;
    var perIface = details.per_interface || {};
    var timeToBlock = details.time_to_block;

    var html =
      '<div class="result-status ' + status + '">' +
        '<span class="status-icon">' + statusIcon(status) + '</span>' +
        '<span>' + status.toUpperCase() + '</span>' +
      '</div>' +
      '<table class="result-table">' +
        '<tbody>' +
          '<tr><td>Duration</td><td>' + (duration != null ? duration + 's' : '--') + '</td></tr>' +
          '<tr><td>Total Packets</td><td>' + (totalPkts != null ? totalPkts : '--') + '</td></tr>' +
          '<tr><td>Tunnel Packets</td><td>' + (tunnelPkts != null ? tunnelPkts : '--') + '</td></tr>' +
          '<tr><td>Leaked Packets</td><td>' + (leakedPkts != null ? leakedPkts : '--') + '</td></tr>' +
        '</tbody>' +
      '</table>';

    if (leakedPkts != null && leakedPkts > 0) {
      // Show per-interface breakdown
      var ifaceNames = [];
      for (var key in perIface) {
        if (perIface.hasOwnProperty(key)) {
          ifaceNames.push(key);
        }
      }
      if (ifaceNames.length) {
        html +=
          '<table class="result-table">' +
            '<thead><tr><th>Interface</th><th>Leaked</th></tr></thead>' +
            '<tbody>';
        for (var i = 0; i < ifaceNames.length; i++) {
          html +=
            '<tr>' +
              '<td>' + escapeHtml(ifaceNames[i]) + '</td>' +
              '<td>' + perIface[ifaceNames[i]] + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
      }
      if (timeToBlock != null) {
        html += '<div class="ks-summary">Time to block: ' + timeToBlock + 's</div>';
      }
    } else if (leakedPkts != null && leakedPkts === 0) {
      html += '<div class="ks-ok">Kill switch held &mdash; no leaks detected</div>';
    }

    if (data.timestamp) {
      html += '<div class="result-timestamp">' + formatTimestamp(data.timestamp) + '</div>';
    }

    el.innerHTML = html;
  }

  function renderFullResult(el, data) {
    // Full audit returns {leaks: {...}, fingerprint: {...}, killswitch: {...}}
    var modules = ["leaks", "fingerprint", "killswitch"];
    var labels = { leaks: "Leak Detection", fingerprint: "Fingerprinting", killswitch: "Kill Switch" };
    var overallStatus = "pass";

    var subsHtml = '';
    for (var i = 0; i < modules.length; i++) {
      var key = modules[i];
      var mod = data[key];
      if (!mod) continue;

      var st = mod.status || "warning";
      if (st === "fail") overallStatus = "fail";
      else if (st === "warning" && overallStatus !== "fail") overallStatus = "warning";

      subsHtml +=
        '<div class="sub-result">' +
          '<span class="sub-result-label">' + labels[key] + '</span>' +
          '<span class="sub-result-status ' + st + '">' + statusIcon(st) + ' ' + st.toUpperCase() + '</span>' +
        '</div>';

      // Also update individual cards
      var individualEl = document.getElementById("result-" + key);
      if (individualEl) {
        renderSingleResult(individualEl, mod, key);
      }
    }

    el.className = "card-result status-" + overallStatus;

    var html =
      '<div class="result-status ' + overallStatus + '">' +
        '<span class="status-icon">' + statusIcon(overallStatus) + '</span>' +
        '<span>OVERALL: ' + overallStatus.toUpperCase() + '</span>' +
      '</div>' +
      '<div class="full-sub-results">' + subsHtml + '</div>';

    el.innerHTML = html;
  }

  function fetchStoredResults() {
    dom.btnFetchResults.disabled = true;

    fetch("/api/results")
      .then(function (response) {
        if (!response.ok) throw new Error("Failed to fetch results");
        return response.json();
      })
      .then(function (data) {
        if (data.leaks) {
          renderSingleResult(dom.resultLeaks, data.leaks, "leaks");
        }
        if (data.fingerprint) {
          renderSingleResult(dom.resultFingerprint, data.fingerprint, "fingerprint");
        }
        if (data.killswitch) {
          renderSingleResult(dom.resultKillswitch, data.killswitch, "killswitch");
        }
        if (data.full) {
          renderFullResult(dom.resultFull, data.full);
        }
      })
      .catch(function (err) {
        console.error("Failed to fetch stored results:", err);
      })
      .finally(function () {
        dom.btnFetchResults.disabled = false;
      });
  }

  // ---- Utilities ----

  function statusIcon(status) {
    switch (status) {
      case "pass": return "&#10003;"; // checkmark
      case "fail": return "&#10007;"; // X mark
      case "warning": return "&#9888;"; // warning triangle
      default: return "?";
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  function formatTimestamp(ts) {
    if (!ts) return "--";
    try {
      var d = new Date(ts);
      return d.toLocaleString();
    } catch (e) {
      return ts;
    }
  }

  function formatTime(ts) {
    if (!ts) return "";
    try {
      var d = new Date(ts);
      return d.toLocaleTimeString();
    } catch (e) {
      return "";
    }
  }

  // ---- Initialize ----

  function init() {
    bindAuditButtons();
    connectWebSocket();
  }

  // Start when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
