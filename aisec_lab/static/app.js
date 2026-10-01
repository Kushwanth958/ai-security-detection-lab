"use strict";
const $ = id => document.getElementById(id);
const state = {trials: [], page: 0, pageSize: 12, run: null, view: "evaluation", loading: 0};
const rules = {AI001: "Instruction override signal", AI002: "Synthetic secret in output", AI003: "Tool permission denied", AI004: "Sensitive simulated tool action", AI005: "Repeated policy events"};
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function metric(label, value, detail) {
  const element = node("div", undefined, "metric");
  element.append(node("div", label, "metric-label"), node("div", value, "metric-value"), node("div", detail, "metric-detail"));
  return element;
}
function pct(value) { return value.rate === null ? "N/A" : (value.rate * 100).toFixed(1) + "%"; }
function count(value) { return `${value.numerator} / ${value.denominator} scored trials`; }
async function fetchJSON(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Could not load evidence (HTTP ${response.status}).`);
  return response.json();
}
function showError(error) { $("message").textContent = error.message || "Could not load evidence."; }
function badge(text, type) { return node("span", text, `badge ${type || ""}`); }
function renderSummary(summary) {
  const data = summary.overall;
  $("metrics").replaceChildren(
    metric("RECORDED TRIALS", data.total_trials.toLocaleString(), `${data.completed_trials} scored · ${data.errors} errors · ${data.review_required} need review`),
    metric("APPLICATION ATTACK SUCCESS", pct(data.attack_success), count(data.attack_success)),
    metric("MODEL BOUNDARY VIOLATIONS", pct(data.model_boundary_violation), count(data.model_boundary_violation)),
    metric("LEGITIMATE TASK COMPLETION", pct(data.legitimate_task_completion), "Keyword / tool proxies · inspect evidence")
  );
  $("comparison").replaceChildren();
  const grouped = new Map();
  for (const group of summary.groups) {
    const key = `${group.source} / ${group.model_id}`;
    if (!grouped.has(key)) grouped.set(key, {});
    grouped.get(key)[group.mode] = group;
  }
  for (const [name, modes] of grouped) {
    const row = node("div", undefined, "comparison-row");
    row.append(node("div", name, "comparison-label"));
    for (const mode of ["baseline", "secured"]) {
      if (!modes[mode]) continue;
      const metricValue = modes[mode].attack_success;
      const track = node("div", undefined, "bar-track");
      const bar = node("span", undefined, `bar ${mode}`);
      // The only dynamic CSS value is a validated numeric fraction.
      const fraction = Number.isFinite(metricValue.rate) ? Math.max(0, Math.min(1, metricValue.rate)) : 0;
      bar.style.transform = `scaleX(${fraction})`;
      track.append(bar);
      row.append(track, node("div", `${mode}: ${pct(metricValue)} · ${count(metricValue)}`, "bar-values"));
    }
    $("comparison").append(row);
  }
  $("detections").replaceChildren();
  for (const [id, label] of Object.entries(rules)) {
    const row = node("div", undefined, "detection-row");
    const description = node("div");
    description.append(node("span", id, "rule-id"), node("span", label, "rule-name"));
    row.append(description, node("span", String(data.rule_counts[id] || 0), "rule-count"));
    $("detections").append(row);
  }
  $("provenance").textContent = JSON.stringify(summary.run.metadata, null, 2);
}
function filteredTrials() {
  const query = $("search").value.toLowerCase();
  const mode = $("mode-filter").value;
  const outcome = $("outcome-filter").value;
  return state.trials.filter(trial => {
    const searchable = `${trial.case_id} ${trial.model_id} ${trial.category}`.toLowerCase();
    return (!query || searchable.includes(query)) && (!mode || trial.mode === mode) &&
      (!outcome || (outcome === "success" ? trial.status === "completed" && trial.application_success === true :
        outcome === "failure" ? trial.status === "completed" && trial.application_success === false : trial.status === outcome));
  });
}
function renderTrials() {
  const trials = filteredTrials();
  const pages = Math.max(1, Math.ceil(trials.length / state.pageSize));
  state.page = Math.min(state.page, pages - 1);
  $("trial-count").textContent = `${trials.length} matching trials`;
  $("page-info").textContent = `Page ${state.page + 1} of ${pages}`;
  $("previous").disabled = state.page === 0;
  $("next").disabled = state.page >= pages - 1;
  $("trials").replaceChildren();
  for (const trial of trials.slice(state.page * state.pageSize, (state.page + 1) * state.pageSize)) {
    const row = node("tr");
    const identity = node("td", trial.case_id);
    identity.append(node("small", `${trial.model_id} · ${trial.source} · repeat ${trial.repetition}`));
    const mode = node("td"); mode.append(badge(trial.mode));
    const result = node("td");
    let text, type;
    if (trial.status !== "completed") {text = trial.status === "error" ? "Error" : "Needs review"; type = "warn";}
    else if (trial.adversarial) {text = trial.application_success ? "Attack succeeded" : "Attack not achieved"; type = trial.application_success ? "bad" : "good";}
    else {text = trial.application_success ? "Task completed" : "Task not completed"; type = trial.application_success ? "good" : "warn";}
    result.append(badge(text, type));
    const signals = node("td", [...new Set(trial.detections.map(d => d.rule_id))].join(" · ") || "—");
    const evidence = node("td");
    const button = node("button", "Inspect ↗", "evidence-button");
    button.addEventListener("click", () => {
      $("evidence-title").textContent = trial.case_id;
      $("evidence-content").textContent = JSON.stringify(trial, null, 2);
      $("evidence-dialog").showModal();
    });
    evidence.append(button); row.append(identity, mode, result, signals, evidence); $("trials").append(row);
  }
  if (!trials.length) {
    const row = node("tr"), cell = node("td", "No trials match these filters.", "empty");
    cell.colSpan = 5; row.append(cell); $("trials").append(row);
  }
}
async function loadRun(id) {
  const generation = ++state.loading;
  try {
    const data = await fetchJSON(`/api/run?id=${encodeURIComponent(id)}`);
    if (generation !== state.loading) return;
    state.run = data.summary.run; state.trials = data.trials; state.page = 0;
    if (state.view === "evaluation") $("message").textContent = state.run.metadata.warning;
    $("run-meta").textContent = `${new Date(state.run.created_at).toLocaleString()} · ${state.run.metadata.case_count} cases`;
    renderSummary(data.summary); renderTrials();
  } catch (error) { showError(error); }
}
async function loadSOC() {
  try {
    const report = await fetchJSON("/api/soc");
    if (state.view !== "soc") return;
    $("message").textContent = report.warning;
    $("soc-alerts").replaceChildren(); $("soc-metrics").replaceChildren();
    if (!report.summary) return;
    $("soc-metrics").append(
      metric("LAB ALERTS", String(report.summary.total), "Synthetic, labeled event groups"),
      metric("VALID STRUCTURED OUTPUTS", String(report.summary.valid_outputs), "Schema validation only"),
      metric("GROUND-TRUTH VERDICTS", String(report.summary.verdict_matches), "Severity + disposition matches"),
      metric("MISSING EVIDENCE", String(report.summary.missing_evidence_alerts), "Required event references omitted")
    );
    for (const alert of report.alerts) {
      const card = node("article", undefined, "panel soc-card");
      const heading = node("div", undefined, "panel-heading");
      heading.append(node("h2", alert.alert_id), badge("Human review", "warn")); card.append(heading);
      const info = node("dl");
      const value = alert.enrichment.value;
      for (const [label, detail] of [["Model / source", `${alert.model_id} / ${alert.source}`], ["Asset owner", alert.asset.owner || "Unknown"],
        ["Rule verdict", `${alert.baseline.severity} / ${alert.baseline.disposition}`], ["AI verdict", value ? `${value.severity} / ${value.disposition}` : "Invalid output"],
        ["Unsupported refs", alert.enrichment.unsupported_evidence_ids.join(", ") || "None"], ["Missing refs", alert.missing_required_evidence.join(", ") || "None"]]) {
        info.append(node("dt", label), node("dd", detail));
      }
      card.append(info, node("p", value ? value.summary : (alert.error || alert.enrichment.error || "Human review required"), "footnote"));
      const timeline = node("ol", undefined, "timeline");
      for (const event of alert.timeline) {
        const item = node("li", `${event.id} · ${event.type.replaceAll("_", " ")}`);
        const time = node("time", `${event.timestamp} · ${event.user} · ${event.host}`);
        time.dateTime = event.timestamp; item.append(time); timeline.append(item);
      }
      const details = node("details"); details.append(node("summary", "Inspect full evidence"), node("pre", JSON.stringify(alert, null, 2)));
      card.append(timeline, details); $("soc-alerts").append(card);
    }
  } catch (error) { showError(error); }
}
function changeView(view) {
  state.view = view;
  $("evaluation-view").hidden = view !== "evaluation"; $("soc-view").hidden = view !== "soc";
  for (const tab of ["evaluation", "soc"]) {
    $(tab + "-tab").classList.toggle("active", tab === view);
    $(tab + "-tab").setAttribute("aria-pressed", String(tab === view));
  }
  $("page-title").textContent = view === "soc" ? "SOC investigations" : "Model evaluations";
  $("page-description").textContent = view === "soc" ? "Correlate events, inspect cited evidence, and review the assistant's verdict." :
    "Trace the boundary between a model's behavior and an application's controls.";
  if (view === "soc") loadSOC();
  else $("message").textContent = state.run ? state.run.metadata.warning : "Run python -m aisec_lab demo to populate this view.";
}
$("evaluation-tab").addEventListener("click", () => changeView("evaluation"));
$("soc-tab").addEventListener("click", () => changeView("soc"));
$("run-select").addEventListener("change", event => loadRun(event.target.value));
for (const id of ["search", "mode-filter", "outcome-filter"]) $(id).addEventListener("input", () => {state.page = 0; renderTrials();});
$("previous").addEventListener("click", () => {state.page--; renderTrials();});
$("next").addEventListener("click", () => {state.page++; renderTrials();});
$("close-dialog").addEventListener("click", () => $("evidence-dialog").close());
(async () => {
  try {
    const runs = await fetchJSON("/api/runs");
    for (const run of runs) {
      const option = node("option", `${run.id.slice(0, 8)} · ${run.metadata.sources.join(", ")}`);
      option.value = run.id; $("run-select").append(option);
    }
    if (runs.length) await loadRun(runs[0].id);
    else {$("message").textContent = "No evaluations yet. Run python -m aisec_lab demo, then refresh."; $("run-select").disabled = true;}
  } catch (error) { showError(error); }
})();
