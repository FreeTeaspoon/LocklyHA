/* Lockly management: authenticated WebSocket only; PINs never enter HA services. */
class LocklyManagementCard extends HTMLElement {
  constructor() { super(); this.attachShadow({mode: "open"}); this.busy = false; }
  setConfig(config) { this.config = config; }
  getCardSize() { return 8; }
  set hass(hass) {
    this._hass = hass;
    if (!this.ready) { this.ready = true; this.initialise(); }
  }
  async initialise() {
    this.shadowRoot.innerHTML = `<style>
      :host{display:block}ha-card{padding:20px;color:var(--primary-text-color)}
      h2{font-size:20px;margin:0 0 8px}h3{font-size:16px;margin:24px 0 12px}
      p{line-height:1.5;margin:8px 0;color:var(--secondary-text-color)}
      button,input,select{font:inherit;box-sizing:border-box;border:1px solid var(--divider-color,#aaa);border-radius:8px;
        background:var(--card-background-color,#fff);color:var(--primary-text-color,#222);min-height:42px;padding:8px 12px}
      button{cursor:pointer}button:active{transform:scale(.98)}button:disabled{opacity:.55;cursor:wait}
      button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid var(--primary-color);outline-offset:2px}
      .row,.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row{justify-content:space-between;margin:10px 0}
      .entry{padding:12px 0;border-bottom:1px solid var(--divider-color)}.entry p{font-size:14px}
      form{display:grid;gap:12px}label{display:grid;gap:6px}input,select{width:100%}
      input[type=checkbox]{width:22px;height:22px;min-height:0;accent-color:var(--primary-color)}
      .check{display:flex;gap:10px;align-items:center}.days{display:flex;flex-wrap:wrap;gap:12px}
      [hidden]{display:none!important}#message{min-height:1.5em;overflow-wrap:anywhere}#history{max-height:350px;overflow:auto}
      @media(prefers-reduced-motion:reduce){button:active{transform:none}}
    </style><ha-card><h2>Lock settings & access</h2>
      <p id="description">Manage PINs stored on your lock. Refresh reads the lock and may beep.</p>
      <label id="choose">Lock<select id="lock"></select></label>
      <div class="actions"><button id="refresh">Refresh settings & PINs</button><button id="read-history">Read history</button></div>
      <p id="updated"></p><p id="message" role="status" aria-live="polite"></p>
      <section id="settings"><h3>Settings</h3><div id="switches"></div>
        <label>Hub doorbell volume<select id="hub-volume" disabled><option value="0">Mute</option><option value="1">Low</option><option value="2">High</option></select></label>
      </section>
      <section><div class="row"><h3>Access PINs</h3><button id="add">Add PIN</button></div><div id="credentials"></div></section>
      <form id="editor" hidden><h3 id="form-title">Add PIN</h3>
        <label>Name<input id="name" required maxlength="20" autocomplete="off"></label>
        <label id="pin-label">PIN<input id="pin" type="password" inputmode="numeric" pattern="[0-9]{6,8}"
          minlength="6" maxlength="8" autocomplete="new-password"></label>
        <p id="pin-help">Use 6 to 8 digits. The PIN is sent only when you save.</p>
        <label>Access schedule<select id="schedule"><option value="always">Always</option><option value="temporary">Date range</option>
          <option value="recurring">Weekly schedule</option></select></label>
        <p id="zone"></p>
        <div id="dates" hidden><label>Starts<input id="date-start" type="datetime-local"></label>
          <label>Ends<input id="date-end" type="datetime-local"></label></div>
        <div id="weekly" hidden><div class="days" id="days"></div><label>From<input id="time-start" type="time"></label>
          <label>Until<input id="time-end" type="time"></label></div>
        <div class="actions"><button type="submit">Save to lock</button><button id="cancel" type="button">Cancel</button></div>
      </form>
      <section><h3>Access history</h3><p>History is read on demand.</p><div id="history"></div></section>
    </ha-card>`;
    this.$ = id => this.shadowRoot.getElementById(id);
    if (!this._hass.user?.is_admin) {
      this.shadowRoot.querySelectorAll("section,form,.actions,#choose").forEach(e => e.hidden = true);
      this.$("description").textContent = "A Home Assistant administrator account is required to manage access.";
      return;
    }
    this.$("hub-volume").onchange = async () => {
      const old = this.data.hub_volume;
      if (!await this.run("hub_volume", {value: Number(this.$("hub-volume").value)})) this.$("hub-volume").value = old;
    };
    this.$("refresh").onclick = () => this.run("refresh");
    this.$("read-history").onclick = () => this.run("history");
    this.$("add").onclick = () => this.edit();
    this.$("cancel").onclick = () => this.closeEditor();
    this.$("schedule").onchange = () => this.scheduleChanged();
    this.$("lock").onchange = () => { this.closeEditor(); this.data = this.locks.find(l => l.lock_id === this.$("lock").value); this.render(); };
    ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].forEach((day, i) => {
      const label = document.createElement("label"); label.className = "check";
      const input = document.createElement("input"); input.type = "checkbox"; input.value = 1 << i;
      label.append(input, day); this.$("days").append(label);
    });
    this.$("editor").onsubmit = event => { event.preventDefault(); this.save(); };
    try {
      const result = await this._hass.callWS({type: "lockly/management", action: "get"});
      this.locks = result.locks;
      this.locks.forEach(lock => { const option = document.createElement("option"); option.value = lock.lock_id; option.textContent = lock.name; this.$("lock").append(option); });
      this.data = this.locks.find(l => l.lock_id === this.config.lock_id) || this.locks[0];
      if (!this.data) { this.$("message").textContent = "No supported PGD898S lock was found."; return; }
      this.$("lock").value = this.data.lock_id;
      this.render();
    } catch (e) { this.$("message").textContent = e.message || "Could not connect to Lockly management."; }
  }
  async run(action, values = {}) {
    if (this.busy || !this.data) return false;
    this.busy = true; this.disable(true); this.$("message").textContent = "Reading the lock…";
    if (["setting", "save_pin", "delete_pin", "hub_volume"].includes(action)) this.$("message").textContent = "Applying and checking the change…";
    try {
      this.data = await this._hass.callWS({type: "lockly/management", lock_id: this.data.lock_id, action, ...values});
      this.locks[this.locks.findIndex(l => l.lock_id === this.data.lock_id)] = this.data;
      this.render(); this.$("message").textContent = ["setting", "save_pin", "delete_pin", "hub_volume"].includes(action) ? "Confirmed on the lock." : "Lock information refreshed.";
      return true;
    } catch (e) { this.$("message").textContent = e.message || "The lock did not confirm the operation. Refresh before retrying."; return false; }
    finally { this.busy = false; this.disable(false); }
  }
  disable(value) {
    this.shadowRoot.querySelectorAll("button,input,select").forEach(e => e.disabled = value);
    this.$("hub-volume").disabled = value || this.data?.hub_volume == null;
  }
  render() {
    this.$("updated").textContent = this.data.updated_at ? `Last read: ${new Date(this.data.updated_at).toLocaleString()}` : "Press Refresh to read settings and PINs.";
    this.$("hub-volume").disabled = this.data.hub_volume == null;
    if (this.data.hub_volume != null) this.$("hub-volume").value = this.data.hub_volume;
    this.$("switches").replaceChildren();
    const labels = {pin_genie: "PIN Genie", keypad_sound: "Keypad sound", auto_lock_enabled: "Auto-lock", bluetooth_sound: "Bluetooth sound", fingerprint_sound: "Fingerprint enrollment sound"};
    Object.entries(this.data.settings).forEach(([key, enabled]) => {
      const label = document.createElement("label"); label.className = "row"; label.append(labels[key] || key);
      const input = document.createElement("input"); input.type = "checkbox"; input.checked = enabled; input.role = "switch";
      input.onchange = async () => { const ok = await this.run("setting", {key, enabled: input.checked}); if (!ok) input.checked = enabled; };
      label.append(input); this.$("switches").append(label);
    });
    this.$("credentials").replaceChildren();
    this.data.credentials.forEach(entry => {
      const row = document.createElement("div"); row.className = "entry";
      const title = document.createElement("strong"); title.textContent = entry.name;
      const detail = document.createElement("p"); detail.textContent = `Slot ${entry.slot} · ${this.describeSchedule(entry.schedule)}${entry.editable ? "" : " · Protected"}`;
      row.append(title, detail);
      if (entry.editable) {
        const actions = document.createElement("div"); actions.className = "actions";
        const edit = document.createElement("button"); edit.textContent = "Edit"; edit.onclick = () => this.edit(entry);
        const remove = document.createElement("button"); remove.textContent = "Delete";
        remove.onclick = () => { if (confirm(`Delete ${entry.name} (slot ${entry.slot}) from the lock?`)) this.run("delete_pin", {slot: entry.slot}); };
        actions.append(edit, remove); row.append(actions);
      }
      this.$("credentials").append(row);
    });
    this.$("history").replaceChildren();
    this.data.history.forEach(event => {
      const row = document.createElement("div"); row.className = "entry";
      const who = event.operator || (event.pid == null ? "No credential" : `Credential slot ${event.pid}`);
      row.textContent = `${new Date(event.tm).toLocaleString()} · ${event.event_type || `Event ${event.co}`} · ${who}`;
      this.$("history").append(row);
    });
  }
  describeSchedule(s) {
    if (s.type === "always") return "Always";
    if (s.type === "temporary") return `${s.start.replace("T", " ")} – ${s.end.replace("T", " ")}`;
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].filter((_, i) => s.weekdays & (1 << i));
    return `${days.join(", ")} ${s.start}–${s.end}`;
  }
  edit(entry) {
    this.editingSlot = entry?.slot;
    this.$("editor").reset(); this.$("editor").hidden = false;
    this.$("form-title").textContent = entry ? `Edit ${entry.name}` : "Add PIN";
    this.$("name").value = entry?.name || ""; this.$("pin").required = !entry;
    this.$("pin-help").textContent = entry ? "Leave PIN blank to keep the existing code." : "Use 6 to 8 digits. The PIN is sent only when you save.";
    const s = entry?.schedule || {type: "always"}; this.$("schedule").value = s.type;
    if (s.type === "temporary") { this.$("date-start").value = s.start; this.$("date-end").value = s.end; }
    if (s.type === "recurring") {
      this.$("days").querySelectorAll("input").forEach(e => e.checked = !!(s.weekdays & Number(e.value)));
      this.$("time-start").value = s.start; this.$("time-end").value = s.end;
    }
    this.$("zone").textContent = `Schedule time zone: ${this.data.timezone}`;
    this.scheduleChanged(); this.$("name").focus();
  }
  scheduleChanged() {
    const type = this.$("schedule").value;
    this.$("dates").hidden = type !== "temporary"; this.$("weekly").hidden = type !== "recurring";
    ["date-start", "date-end"].forEach(id => this.$(id).required = type === "temporary");
    ["time-start", "time-end"].forEach(id => this.$(id).required = type === "recurring");
  }
  async save() {
    const type = this.$("schedule").value; const schedule = {type};
    if (type === "temporary") { schedule.start = this.$("date-start").value; schedule.end = this.$("date-end").value; }
    if (type === "recurring") {
      schedule.weekdays = [...this.$("days").querySelectorAll("input:checked")].reduce((v, e) => v | Number(e.value), 0);
      schedule.start = this.$("time-start").value; schedule.end = this.$("time-end").value;
    }
    const values = {name: this.$("name").value, pin: this.$("pin").value, schedule};
    if (this.editingSlot !== undefined) values.slot = this.editingSlot;
    this.$("pin").value = "";
    if (await this.run("save_pin", values)) this.closeEditor();
    values.pin = "";
  }
  closeEditor() { this.$("editor").reset(); this.$("editor").hidden = true; this.editingSlot = undefined; this.$("add").focus(); }
  disconnectedCallback() { if (this.$) this.$("pin").value = ""; }
}
customElements.define("lockly-management-card", LocklyManagementCard);
window.customCards = window.customCards || [];
window.customCards.push({type: "lockly-management-card", name: "Lockly access management", description: "PGD898S settings, PIN schedules and access history"});
