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
          <option value="recurring">Weekly schedule</option><option value="one_time">One use</option></select></label>
        <p id="zone"></p>
        <div id="dates" hidden><label>Starts<input id="date-start" type="datetime-local"></label>
          <label>Ends<input id="date-end" type="datetime-local"></label></div>
        <div id="weekly" hidden><div class="days" id="days"></div><label>From<input id="time-start" type="time"></label>
          <label>Until<input id="time-end" type="time"></label></div>
        <div class="actions"><button type="submit">Save to lock</button><button id="cancel" type="button">Cancel</button></div>
      </form>
      <section><div class="row"><h3>Fingerprints</h3><button id="read-fingers">Refresh fingerprints</button></div>
        <div id="fingers"></div><form id="enroll-form"><label>New fingerprint name<input id="finger-name" required maxlength="20"></label>
          <button type="submit" id="enroll">Start enrollment</button></form>
        <p id="enrollment" role="status"></p><div class="actions" id="enrollment-actions" hidden>
          <button id="finish-enrollment">Finish & check</button><button id="cancel-enrollment">Stop enrollment</button></div>
      </section>
      <section><div class="row"><h3>Shared eKeys</h3><button id="read-shares">Refresh eKeys</button></div>
        <p>Create an eKey for an always-access guest PIN. The recipient imports it in Lockly. New eKeys grant local door access.
          Revoking an eKey does not delete its keypad PIN. Delete that PIN separately to remove keypad access.</p>
        <div id="shares"></div><form id="share-form"><label>Guest PIN<select id="share-pin" required></select></label>
          <button type="submit">Create eKey</button></form>
        <label id="share-secret-label" hidden>eKey, visible for 30 seconds<input id="share-secret" readonly autocomplete="off"></label>
        <button id="hide-share" hidden>Hide eKey</button>
      </section>
      <section><h3>Camera audio & recordings</h3>
        <p>Live view and playback stop after two minutes, or when this card closes. Turning the microphone off closes the camera.</p>
        <div class="actions"><button id="live">Open live view with audio</button><button id="stop-media" disabled>Close camera</button>
          <button id="talk" disabled aria-pressed="false">Turn microphone on</button><button id="read-clips">Refresh recordings</button></div>
        <img id="media-image" hidden alt="Front door camera" style="width:100%;margin-top:12px;border-radius:8px">
        <p id="media-status" role="status"></p><p id="storage"></p><div id="clips"></div>
      </section>
      <section><h3>Access history</h3><p>History is read on demand.</p><div id="history"></div></section>
    </ha-card>`;
    this.$ = id => this.shadowRoot.getElementById(id);
    if (!this._hass.user?.is_admin) {
      this.shadowRoot.querySelectorAll("section,form,.actions,#choose").forEach(e => e.hidden = true);
      this.$("description").textContent = "A Home Assistant administrator account is required to manage access.";
      return;
    }
    this.$("read-fingers").onclick = () => this.run("fingerprints");
    this.$("read-shares").onclick = () => this.run("shares");
    this.$("read-clips").onclick = () => this.run("recordings");
    this.$("enroll-form").onsubmit = event => { event.preventDefault(); this.run("enroll_fingerprint", {name: this.$("finger-name").value}); };
    this.$("finish-enrollment").onclick = () => this.run("finish_enrollment");
    this.$("cancel-enrollment").onclick = () => this.run("cancel_enrollment");
    this.$("share-form").onsubmit = event => {
      event.preventDefault(); const entry = this.data.credentials.find(e => String(e.slot) === this.$("share-pin").value);
      if (entry) this.run("create_share", {slot: entry.slot, revision: entry.revision});
    };
    this.$("hide-share").onclick = () => this.hideShare();
    this.$("live").onclick = () => this.startMedia();
    this.$("stop-media").onclick = () => this.stopMedia();
    this.$("talk").onclick = () => this.toggleTalk();
    this._visibility = () => { if (document.hidden) this.stopMedia(); };
    document.addEventListener("visibilitychange", this._visibility);
    this.$("hub-volume").onchange = async () => {
      const old = this.data.hub_volume;
      if (!await this.run("hub_volume", {value: Number(this.$("hub-volume").value)})) this.$("hub-volume").value = old;
    };
    this.$("refresh").onclick = () => this.run("refresh");
    this.$("read-history").onclick = () => this.run("history");
    this.$("add").onclick = () => this.edit();
    this.$("cancel").onclick = () => this.closeEditor();
    this.$("schedule").onchange = () => this.scheduleChanged();
    this.$("lock").onchange = () => { this.stopMedia(); this.hideShare(); this.closeEditor(); this.data = this.locks.find(l => l.lock_id === this.$("lock").value); this.render(); };
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
    this.$("stop-media").disabled = !this.mediaToken;
    this.$("live").disabled = value || !!this.mediaToken;
    this.$("talk").disabled = value || !this.mediaToken || !!this.mediaClip;
    this.$("enroll").disabled = value || !!this.data?.enrollment?.active;
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
      const detail = document.createElement("p"); detail.textContent = `Slot ${entry.slot} · ${entry.kind === "one_time" ? "One use" : this.describeSchedule(entry.schedule)}${entry.editable ? "" : " · Protected"}`;
      row.append(title, detail);
      if (entry.editable) {
        const actions = document.createElement("div"); actions.className = "actions";
        const edit = document.createElement("button"); edit.textContent = "Edit"; edit.onclick = () => this.edit(entry);
        const remove = document.createElement("button"); remove.textContent = "Delete";
        remove.onclick = () => { if (confirm(`Delete ${entry.name} (slot ${entry.slot}) from the lock?`)) this.run("delete_pin", {slot: entry.slot, revision: entry.revision}); };
        actions.append(edit, remove); row.append(actions);
      }
      this.$("credentials").append(row);
    });
    this.renderExtensions();
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
    this.editingSlot = entry?.slot; this.editingRevision = entry?.revision;
    this.$("editor").reset(); this.$("editor").hidden = false;
    this.$("form-title").textContent = entry ? `Edit ${entry.name}` : "Add PIN";
    this.$("name").value = entry?.name || ""; this.$("pin").required = !entry;
    this.$("pin-help").textContent = entry ? "Leave PIN blank to keep the existing code." : "Use 6 to 8 digits. The PIN is sent only when you save.";
    const s = entry?.schedule || {type: "always"}; this.$("schedule").value = entry?.kind === "one_time" ? "one_time" : s.type;
    if (s.type === "temporary") { this.$("date-start").value = s.start; this.$("date-end").value = s.end; }
    if (s.type === "recurring") {
      this.$("days").querySelectorAll("input").forEach(e => e.checked = !!(s.weekdays & Number(e.value)));
      this.$("time-start").value = s.start; this.$("time-end").value = s.end;
    }
    this.$("zone").textContent = `Schedule time zone: ${this.data.timezone}`;
    [...this.$("schedule").options].forEach(option => {
      option.disabled = !!entry && ((option.value === "one_time") !== (entry.kind === "one_time"));
    });
    this.scheduleChanged(); this.$("name").focus();
  }
  scheduleChanged() {
    const type = this.$("schedule").value;
    this.$("dates").hidden = type !== "temporary"; this.$("weekly").hidden = type !== "recurring";
    ["date-start", "date-end"].forEach(id => this.$(id).required = type === "temporary");
    ["time-start", "time-end"].forEach(id => this.$(id).required = type === "recurring");
  }
  async save() {
    const type = this.$("schedule").value; const schedule = {type: type === "one_time" ? "always" : type};
    if (type === "temporary") { schedule.start = this.$("date-start").value; schedule.end = this.$("date-end").value; }
    if (type === "recurring") {
      schedule.weekdays = [...this.$("days").querySelectorAll("input:checked")].reduce((v, e) => v | Number(e.value), 0);
      schedule.start = this.$("time-start").value; schedule.end = this.$("time-end").value;
    }
    const values = {name: this.$("name").value, pin: this.$("pin").value, schedule, one_time: type === "one_time"};
    if (this.editingSlot !== undefined) { values.slot = this.editingSlot; values.revision = this.editingRevision; }
    this.$("pin").value = "";
    if (await this.run("save_pin", values)) this.closeEditor();
    values.pin = "";
  }
  ws(action, values = {}) {
    return this._hass.callWS({type: "lockly/management", lock_id: this.data.lock_id, action, ...values});
  }
  button(text, action) {
    const button = document.createElement("button"); button.textContent = text; button.onclick = action; return button;
  }
  hideShare() {
    clearTimeout(this.secretTimer); this.$("share-secret").value = "";
    this.$("share-secret-label").hidden = this.$("hide-share").hidden = true;
  }
  async revealShare(entry) {
    this.hideShare();
    try {
      const result = await this.ws("reveal_share", {share_id: entry.id, revision: entry.revision});
      this.$("share-secret").value = result.token; result.token = "";
      this.$("share-secret-label").hidden = this.$("hide-share").hidden = false;
      this.$("share-secret").focus(); this.$("share-secret").select();
      this.secretTimer = setTimeout(() => this.hideShare(), 30000);
    } catch (e) { this.$("message").textContent = e.message || "Could not reveal the eKey."; }
  }
  renderExtensions() {
    this.$("fingers").replaceChildren();
    (this.data.fingerprints || []).forEach(entry => {
      const row = document.createElement("div"); row.className = "entry";
      const name = document.createElement("p"); name.textContent = `${entry.name} · Slot ${entry.slot}${entry.delegated ? " · Delegated" : ""}`; row.append(name);
      if (!entry.delegated) {
        const actions = document.createElement("div"); actions.className = "actions";
        actions.append(this.button("Rename", () => {
          const name = prompt("Fingerprint name", entry.name);
          if (name) this.run("rename_fingerprint", {slot: entry.slot, revision: entry.revision, name});
        }), this.button("Delete", () => {
          if (confirm(`Delete fingerprint ${entry.name} from the lock?`)) this.run("delete_fingerprint", {slot: entry.slot, revision: entry.revision});
        })); row.append(actions);
      }
      this.$("fingers").append(row);
    });
    const enrollment = this.data.enrollment || {};
    this.$("enrollment").textContent = enrollment.message || "Refresh to list fingerprints, or start enrollment beside the lock.";
    this.$("enrollment-actions").hidden = !enrollment.active;
    clearInterval(this.enrollmentPoll);
    if (enrollment.active) this.enrollmentPoll = setInterval(async () => {
      if (this.busy) return;
      try { this.data = await this.ws("get"); this.renderExtensions(); } catch (_) { clearInterval(this.enrollmentPoll); }
    }, 2000);
    this.$("shares").replaceChildren();
    (this.data.shares || []).forEach(entry => {
      const row = document.createElement("div"); row.className = "entry";
      const name = document.createElement("p"); name.textContent = `${entry.name} · PIN slot ${entry.slot ?? "unknown"}`;
      row.append(name, this.button("Reveal eKey", () => this.revealShare(entry)), this.button("Revoke eKey", () => {
        if (confirm(`Revoke ${entry.name}'s eKey? Its keypad PIN will remain active.`)) this.run("revoke_share", {share_id: entry.id, revision: entry.revision});
      })); this.$("shares").append(row);
    });
    this.$("share-pin").replaceChildren();
    this.data.credentials.filter(e => e.editable && e.kind !== "one_time" && e.schedule.type === "always").forEach(entry => {
      const option = document.createElement("option"); option.value = entry.slot; option.textContent = entry.name; this.$("share-pin").append(option);
    });
    this.$("share-form").hidden = !this.$("share-pin").options.length;
    const storage = this.data.recordings;
    this.$("storage").textContent = storage?.message || (storage ? `${storage.clips.length} recordings in the past seven days.` : "Refresh to check recording storage.");
    this.$("clips").replaceChildren();
    (storage?.clips || []).forEach(clip => {
      const row = document.createElement("div"); row.className = "entry";
      const label = document.createElement("p"); label.textContent = new Date(clip.time).toLocaleString();
      row.append(label, this.button("Play with audio", () => this.startMedia(clip.id)), this.button("Export MP4", () => this.startMedia(clip.id, true)));
      this.$("clips").append(row);
    });
  }
  async startMedia(clip, exporting = false) {
    if (this.mediaStarting) return;
    this.mediaStarting = true;
    try {
      await this.stopMedia();
      const generation = this.mediaGeneration, lock_id = this.data.lock_id;
      if (!this.isConnected) return;
      this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
      await this.audioContext.resume(); this.audioTime = this.audioContext.currentTime;
      if (generation !== this.mediaGeneration || !this.isConnected) return;
      const result = await this.ws("media_start", {lock_id, ...(clip ? {clip_id: clip} : {}), export: exporting});
      if (generation !== this.mediaGeneration || !this.isConnected) {
        await this.ws("media_stop", {lock_id, session: result.session}); return;
      }
      this.mediaLockId = lock_id;
      this.mediaToken = result.session; this.mediaClip = clip; this.exporting = exporting;
      this.$("media-status").textContent = exporting ? "Exporting playback. Keep this card open." : "Connecting to camera…";
      this.disable(this.busy); this.pollMedia();
    } catch (e) { await this.stopMedia(); this.$("media-status").textContent = e.message || "Could not open the camera."; }
    finally { this.mediaStarting = false; }
  }
  async pollMedia() {
    const session = this.mediaToken; if (!session) return;
    try {
      const frame = await this.ws("media_poll", {session, lock_id: this.mediaLockId});
      if (session !== this.mediaToken) return;
      if (frame.jpeg) { this.$("media-image").src = `data:image/jpeg;base64,${frame.jpeg}`; this.$("media-image").hidden = false; }
      if (frame.pcm && this.audioContext) {
        const bytes = Uint8Array.from(atob(frame.pcm), c => c.charCodeAt(0));
        const view = new DataView(bytes.buffer), buffer = this.audioContext.createBuffer(1, bytes.length / 2, 8000);
        const channel = buffer.getChannelData(0); for (let i = 0; i < channel.length; i++) channel[i] = view.getInt16(i * 2, true) / 32768;
        const source = this.audioContext.createBufferSource(); source.buffer = buffer; source.connect(this.audioContext.destination);
        this.audioTime = Math.max(this.audioTime, this.audioContext.currentTime);
        if (this.audioTime > this.audioContext.currentTime + 1) this.audioTime = this.audioContext.currentTime;
        source.start(this.audioTime); this.audioTime += buffer.duration;
      }
      if (frame.error) throw new Error(frame.error);
      if (frame.ended) {
        if (this.exporting) {
          const file = await this.ws("media_download", {session});
          if (session !== this.mediaToken || !this.isConnected) return;
          const bytes = Uint8Array.from(atob(file.file), c => c.charCodeAt(0));
          const url = URL.createObjectURL(new Blob([bytes], {type: "video/mp4"}));
          const link = document.createElement("a"); link.href = url; link.download = file.name; link.click();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
        }
        await this.stopMedia(); this.$("media-status").textContent = "Camera session finished."; return;
      }
      this.$("media-status").textContent = this.exporting ? "Exporting recording…" : this.micStream ? "Microphone is on." : "Camera is open. Microphone is off.";
      this.mediaTimer = setTimeout(() => this.pollMedia(), 400);
    } catch (e) { await this.stopMedia(); this.$("media-status").textContent = e.message || "Camera connection ended."; }
  }
  async stopMedia() {
    this.mediaGeneration = (this.mediaGeneration || 0) + 1;
    const generation = this.mediaGeneration, context = this.audioContext; this.audioContext = null;
    clearTimeout(this.mediaTimer); const session = this.mediaToken, lock_id = this.mediaLockId; this.mediaToken = null;
    await this.stopMicrophone();
    if (session) try { await this.ws("media_stop", {session, lock_id}); } catch (_) {}
    if (context) await context.close().catch(() => {});
    if (generation !== this.mediaGeneration) return;
    this.$("media-image").removeAttribute("src"); this.$("media-image").hidden = true;
    this.$("media-status").textContent = "Camera closed."; this.disable(this.busy);
  }
  async stopMicrophone() {
    if (this.processor) { this.processor.disconnect(); this.processor.onaudioprocess = null; this.processor = null; }
    if (this.micSource) { this.micSource.disconnect(); this.micSource = null; }
    if (this.micStream) { this.micStream.getTracks().forEach(track => track.stop()); this.micStream = null; }
    this.micSamples = []; this.$("talk").textContent = "Turn microphone on"; this.$("talk").setAttribute("aria-pressed", "false");
  }
  alaw(sample) {
    let pcm = Math.max(-32768, Math.min(32767, Math.round(sample * 32768)));
    const mask = pcm >= 0 ? 0xd5 : 0x55; if (pcm < 0) pcm = -pcm - 1;
    pcm = Math.min(pcm, 32767); let segment = 0;
    for (let boundary = 255; segment < 8 && pcm > boundary; boundary = (boundary << 1) | 1) segment++;
    return ((segment << 4) | ((pcm >> (segment < 2 ? 4 : segment + 3)) & 15)) ^ mask;
  }
  async toggleTalk() {
    const session = this.mediaToken, lock_id = this.mediaLockId; if (!session || this.talkBusy) return;
    this.talkBusy = true;
    try {
      if (this.micStream) { await this.stopMedia(); return; }
      const stream = await navigator.mediaDevices.getUserMedia({audio: {echoCancellation: true, noiseSuppression: true}, video: false});
      if (session !== this.mediaToken) { stream.getTracks().forEach(track => track.stop()); return; }
      this.micStream = stream; await this.ws("media_talk", {session, lock_id, enabled: true});
      if (session !== this.mediaToken || !this.audioContext) {
        stream.getTracks().forEach(track => track.stop());
        try { await this.ws("media_stop", {session, lock_id}); } catch (_) {}
        return;
      }
      this.micSource = this.audioContext.createMediaStreamSource(stream);
      this.processor = this.audioContext.createScriptProcessor(2048, 1, 1); this.micSamples = []; this.micPhase = 0;
      this.processor.onaudioprocess = event => {
        const input = event.inputBuffer.getChannelData(0), step = this.audioContext.sampleRate / 8000;
        for (; this.micPhase < input.length; this.micPhase += step) this.micSamples.push(this.alaw(input[Math.floor(this.micPhase)]));
        this.micPhase -= input.length;
        if (this.micSamples.length >= 320 && !this.audioSending) {
          const count = Math.floor(this.micSamples.length / 320) * 320;
          const audio = btoa(String.fromCharCode(...this.micSamples.splice(0, count))); this.audioSending = true;
          this.ws("media_audio", {session, lock_id, audio}).catch(async e => {
            await this.stopMedia(); this.$("media-status").textContent = e.message || "Microphone connection failed.";
          }).finally(() => { this.audioSending = false; });
        }
        if (this.micSamples.length > 3200) this.stopMedia();
      };
      this.micSource.connect(this.processor); this.processor.connect(this.audioContext.destination);
      this.$("talk").textContent = "Turn microphone off"; this.$("talk").setAttribute("aria-pressed", "true");
    } catch (e) {
      await this.stopMicrophone();
      try { await this.ws("media_talk", {session, lock_id, enabled: false}); } catch (_) {}
      this.$("media-status").textContent = e.message || "Microphone could not start.";
    } finally { this.talkBusy = false; }
  }
  closeEditor() { this.$("editor").reset(); this.$("editor").hidden = true; this.editingSlot = undefined; this.$("add").focus(); }
  disconnectedCallback() {
    if (this.$) { this.$("pin").value = ""; this.hideShare(); this.stopMedia(); }
    clearInterval(this.enrollmentPoll); document.removeEventListener("visibilitychange", this._visibility);
  }
}
if (!customElements.get("lockly-management-card")) customElements.define("lockly-management-card", LocklyManagementCard);
window.customCards = window.customCards || [];
if (!window.customCards.some(card => card.type === "lockly-management-card")) {
  window.customCards.push({type: "lockly-management-card", name: "Lockly access management", description: "PGD898S settings, PIN schedules and access history"});
}
