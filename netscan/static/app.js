(function(){
  "use strict";
  var form = document.getElementById("scan-form");
  var targetInput = form.querySelector("[name=target]");
  var portsInput = form.querySelector("[name=ports]");
  var timeoutInput = form.querySelector("[name=timeout]");
  var startBtn = document.getElementById("start-btn");
  var validateBtn = document.getElementById("validate-btn");
  var clearBtn = document.getElementById("clear-btn");
  var scanNotice = document.getElementById("scan-notice");
  var resultsArea = document.getElementById("results-area");
  var resultsTitle = document.getElementById("results-title");
  var resultsMeta = document.getElementById("results-meta");
  var tbody = document.querySelector("#results-table tbody");
  var raw = document.getElementById("results-raw");
  var exportJson = document.getElementById("export-json");
  var exportCsv = document.getElementById("export-csv");
  var exportJsonPhase3 = null;
  var exportCsvPhase3 = null;

  function setNotice(msg, kind){
    scanNotice.textContent = msg || "";
    scanNotice.className = "notice" + (kind ? " " + kind : "");
  }
  function fieldHelp(elId, html){
    document.getElementById(elId).innerHTML = html || "";
  }
  function buildResultsSummary(payload){
    if(!payload || !payload.results || payload.results.length === 0){
      return "No ports returned.";
    }
    var total = payload.results.length;
    var openCount = 0, closedCount = 0, unknownCount = 0, errorCount = 0;
    payload.results.forEach(function(r){
      if(r.state === "open") openCount++;
      else if(r.state === "closed") closedCount++;
      else if(r.state === "unknown") unknownCount++;
      else errorCount++;
    });
    var parts = ["Target: " + (payload.target || "") + " · TCP", "timeout: " + payload.timeout + "s"];
    parts.push("open: " + openCount);
    if(closedCount > 0) parts.push("closed: " + closedCount);
    if(unknownCount > 0){
      parts.push("unknown: " + unknownCount);
      parts.push("Note: a timeout does not prove a closed port. Unresponsive ports may be filtered, slow, or genuinely closed.");
    }
    if(errorCount > 0) parts.push("error: " + errorCount);
    return parts.join(" · ");
  }
  function showResults(title, meta, payload){
    resultsTitle.textContent = title || "Scan results";
    resultsMeta.textContent = meta;
    tbody.innerHTML = "";
    if(!payload || !payload.results || payload.results.length === 0){
      tbody.innerHTML = "<tr><td colspan='4'>No ports returned.</td></tr>";
      return;
    }
    payload.results.forEach(function(r){
      var tr = document.createElement("tr");
      var tdPort = document.createElement("td"); tdPort.textContent = r.port;
      var tdSvc = document.createElement("td"); tdSvc.textContent = r.service;
      var tdState = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "state-badge state-" + (r.state || "unknown");
      badge.textContent = r.state || "unknown";
      tdState.appendChild(badge);
      var tdErr = document.createElement("td");
      tdErr.textContent = r.error || "";
      tr.appendChild(tdPort); tr.appendChild(tdSvc); tr.appendChild(tdState); tr.appendChild(tdErr);
      tbody.appendChild(tr);
    });
    raw.textContent = JSON.stringify(payload, null, 2);
  }
  function startScan(target, ports, timeout){
    setNotice("Starting scan\u2026", "ok");
    var body = JSON.stringify({target: target, ports: ports, timeout: timeout});
    return fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: body,
      credentials: "same-origin"
    }).then(function(r){
      if(!r.ok){
        return r.json().then(function(j){ return Promise.reject(j.error || "Server error"); });
      }
      return r.json();
    });
  }
  function validateOnly(target, ports, subnet){
    var body = {};
    if(target) body.target = target;
    if(ports) body.ports = ports;
    if(subnet) body.subnet = subnet;
    return fetch("/api/validate", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(body),
      credentials: "same-origin"
    }).then(function(r){ return r.json(); });
  }

  function resetForm(){
    form.reset();
    targetInput.value = "127.0.0.1";
    portsInput.value = "22,80,443";
    timeoutInput.value = "1.0";
    setNotice("");
    fieldHelp("target-help");
    fieldHelp("ports-help");
    fieldHelp("timeout-help");
    resultsArea.classList.add("hidden");
  }

  function validateAndRender(target, ports){
    if(!target.trim()){ fieldHelp("target-help","Target is required."); return; }
    if(!ports.trim()){ fieldHelp("ports-help","Ports are required."); return; }
    validateOnly(target, ports).then(function(j){
      var ok = true;
      if(j.target){
        if(!j.target.authorized){
          fieldHelp("target-help", "Not authorized: " + j.target.reason);
          ok = false;
        } else {
          fieldHelp("target-help", "OK: " + j.target.reason);
        }
      }
      if(j.ports && !j.ports.valid){
        fieldHelp("ports-help", "Invalid: " + j.ports.error);
        ok = false;
      } else if(j.ports){
        fieldHelp("ports-help", "OK \u2014 " + j.ports.count + " port(s)");
      }
      startBtn.disabled = !ok;
    }).catch(function(err){ setNotice("Validation request failed: " + (err && err.message ? err.message : err), "error"); });
  }

  form.addEventListener("submit", function(e){
    e.preventDefault();
    var target = targetInput.value.trim();
    var ports = portsInput.value.trim();
    var timeout = parseFloat(timeoutInput.value) || 1.0;

    if(!target || !ports){ setNotice("Fill in target and ports first.", "error"); return; }

    startScan(target, ports, timeout)
      .then(function(payload){
        var meta = buildResultsSummary(payload);
        showResults("Scan results", meta, payload);
        resultsArea.classList.remove("hidden");
        setNotice("Scan complete.", "ok");
      })
      .catch(function(err){
        setNotice("Scan failed: " + (typeof err === "string" ? err : (err && err.error ? err.error : err)), "error");
        resultsArea.classList.remove("hidden");
        showResults("Scan error", "See message above.", {results: []});
      });
  });

  validateBtn.addEventListener("click", function(){
    var target = targetInput.value.trim();
    var ports = portsInput.value.trim();
    validateAndRender(target, ports);
  });

  clearBtn.addEventListener("click", resetForm);

  targetInput.addEventListener("input", function(){ validateAndRender(targetInput.value, portsInput.value); });
  portsInput.addEventListener("input", function(){ validateAndRender(targetInput.value, portsInput.value); });

  exportJson.addEventListener("click", function(){
    var blob = new Blob([raw.textContent], {type:"application/json"});
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "netscan-results.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  exportCsv.addEventListener("click", function(){
    var rows = [["Port","Service","State","Error"]];
    var data = JSON.parse(raw.textContent);
    if(data && data.results){
      data.results.forEach(function(r){
        rows.push([r.port, r.service, r.state, r.error || ""]);
      });
    }
    var csv = rows.map(function(row){ return row.map(function(c){ return '"' + String(c).replace(/"/g,'""') + '"'; }).join(","); }).join("\r\n");
    var blob = new Blob(["\uFEFF" + csv], {type:"text/csv"});
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "netscan-results.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  function downloadBlob(body, filename, mime){
    var blob = new Blob([body], {type: mime});
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function phase3ExportJson(){
    var data = JSON.parse(raw.textContent);
    var exportPayload = {
      target: data.target || (data.target && data.target.value) || "",
      timeout: data.timeout || "",
      mode: data.mode || "tcp",
      results: data.results || [],
      normalized_results: data.normalized_results || buildNormalized(data),
      metadata: data.metadata || {}
    };
    if(!exportPayload.metadata.scan_start && data.results && data.results.length){
      exportPayload.metadata.scan_start = exportPayload.metadata.scan_start || "";
      exportPayload.metadata.scan_end = exportPayload.metadata.scan_end || "";
      exportPayload.metadata.elapsed_seconds = exportPayload.metadata.elapsed_seconds || 0;
      exportPayload.metadata.timeout = exportPayload.metadata.timeout || data.timeout || "";
      exportPayload.metadata.ports_scanned = exportPayload.metadata.ports_scanned || (data.results||[]).length;
      exportPayload.metadata.target = exportPayload.metadata.target || exportPayload.target;
      exportPayload.metadata.mode = exportPayload.metadata.mode || "tcp";
    }
    downloadBlob(JSON.stringify(exportPayload, null, 2), "netscan-structured.json", "application/json");
  }

  function normalizeOrResults(data){
    if(data.normalized_results && data.normalized_results.length){
      return data.normalized_results;
    }
    var src = data.results || [];
    var out = [];
    var target = (data.target && data.target.value) ? data.target.value : (data.target || "");
    src.forEach(function(r){
      out.push(Object.assign({target: target, port: r.port, protocol: "tcp", state: r.state, service: r.service, banner: "", error: r.error || null}));
    });
    return out;
  }

  function buildNormalized(data){
    if(data.normalized_results && data.normalized_results.length){
      return data.normalized_results;
    }
    var src = data.results || [];
    var out = [];
    src.forEach(function(r){
      out.push(Object.assign({target: target, port: r.port, protocol: "tcp", state: r.state, service: r.service, banner: "", error: r.error || null}));
    });
    return out;
  }

  function phase3ExportJson(){
    var data = JSON.parse(raw.textContent);
    var normalized = normalizeOrResults(data);
    var meta = data.metadata || {};
    if(!meta.scan_start && normalized.length){
      meta.scan_start = meta.scan_start || "";
      meta.scan_end = meta.scan_end || "";
      meta.elapsed_seconds = meta.elapsed_seconds || 0;
      meta.timeout = meta.timeout || data.timeout || "";
      meta.ports_scanned = meta.ports_scanned || normalized.length;
      meta.target = meta.target || (data.target && data.target.value) || data.target || "";
      meta.mode = meta.mode || "tcp";
    }
    var exportPayload = {
      target: data.target || (data.target && data.target.value) || "",
      timeout: data.timeout || "",
      mode: data.mode || "tcp",
      results: data.results || [],
      normalized_results: normalized,
      metadata: meta
    };
    downloadBlob(JSON.stringify(exportPayload, null, 2), "netscan-structured.json", "application/json");
  }

  function phase3ExportCsv(){
    var data = JSON.parse(raw.textContent);
    var normalized = normalizeOrResults(data);
    var meta = data.metadata || {};
    var fieldnames = ["target","port","protocol","state","service","banner","error","scan_start","scan_end","elapsed_seconds","timeout","ports_scanned","mode"];
    var csv = fieldnames.join(",") + "\r\n";
    normalized.forEach(function(row, i){
      var cells = fieldnames.map(function(name){
        var v = (row && row[name] !== undefined) ? row[name] : (i === 0 && meta[name] !== undefined ? meta[name] : "");
        if(v === null || v === undefined) v = "";
        var s = String(v);
        return '"' + s.replace(/"/g,'""') + '"';
      });
      csv += cells.join(",") + "\r\n";
    });
    downloadBlob("\uFEFF" + csv, "netscan-structured.csv", "text/csv");
  }

  exportJsonPhase3 = document.getElementById("export-phase3-json");
  exportCsvPhase3 = document.getElementById("export-phase3-csv");
  if(exportJsonPhase3){
    exportJsonPhase3.addEventListener("click", phase3ExportJson);
  }
  if(exportCsvPhase3){
    exportCsvPhase3.addEventListener("click", phase3ExportCsv);
  }

  resetForm();
})();
