/* SafeBond — client-side encrypted private log
   Uses Web Crypto API (PBKDF2 -> AES-GCM). All encryption happens in the
   browser; the server never sees the passphrase or the plaintext entries. */

(() => {
  const STORAGE_KEY = "safebond_vault_v1";

  const lockScreen = document.getElementById("lockScreen");
  const lockTitle = document.getElementById("lockTitle");
  const lockHint = document.getElementById("lockHint");
  const lockError = document.getElementById("lockError");
  const passphraseInput = document.getElementById("passphraseInput");
  const unlockBtn = document.getElementById("unlockBtn");
  const resetBtn = document.getElementById("resetBtn");

  const sbApp = document.getElementById("sbApp");
  const entryForm = document.getElementById("entryForm");
  const entriesList = document.getElementById("entriesList");
  const emptyState = document.getElementById("emptyState");
  const entryCount = document.getElementById("entryCount");
  const exportBtn = document.getElementById("exportBtn");
  const importFile = document.getElementById("importFile");
  const lockAgainBtn = document.getElementById("lockAgainBtn");

  let cryptoKey = null;   // derived AES-GCM key, kept only in memory
  let vaultSalt = null;   // base64
  let entries = [];       // decrypted, in-memory only while unlocked

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function b64ToBuf(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
  }

  async function deriveKey(passphrase, saltB64) {
    const salt = saltB64 ? b64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    return { key, saltB64: bufToB64(salt) };
  }

  async function encryptJSON(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = enc.encode(JSON.stringify(obj));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    return { iv: bufToB64(iv), data: bufToB64(cipher) };
  }

  async function decryptJSON(key, payload) {
    const iv = new Uint8Array(b64ToBuf(payload.iv));
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64ToBuf(payload.data));
    return JSON.parse(dec.decode(plain));
  }

  function getVault() {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  }
  function saveVault(vault) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
  }

  function setLockMode() {
    const vault = getVault();
    if (vault) {
      lockTitle.textContent = "Unlock SafeBond";
      lockHint.textContent = "Enter your passphrase to view your entries.";
      unlockBtn.innerHTML = '<i class="fas fa-unlock"></i> Unlock';
    } else {
      lockTitle.textContent = "Create SafeBond Passphrase";
      lockHint.textContent = "Choose a passphrase. You'll need it every time — it can't be recovered if lost.";
      unlockBtn.innerHTML = '<i class="fas fa-lock"></i> Create Vault';
    }
  }

  async function handleUnlock() {
    lockError.textContent = "";
    const pass = passphraseInput.value;
    if (!pass || pass.length < 4) {
      lockError.textContent = "Passphrase must be at least 4 characters.";
      return;
    }

    const vault = getVault();

    if (!vault) {
      // Create a brand new vault
      const { key, saltB64 } = await deriveKey(pass, null);
      cryptoKey = key;
      vaultSalt = saltB64;
      entries = [];
      const check = await encryptJSON(cryptoKey, { check: "safebond" });
      saveVault({ salt: vaultSalt, check, entries: [] });
      enterApp();
      return;
    }

    try {
      const { key } = await deriveKey(pass, vault.salt);
      await decryptJSON(key, vault.check); // will throw if passphrase is wrong
      cryptoKey = key;
      vaultSalt = vault.salt;
      entries = await Promise.all(vault.entries.map(e => decryptJSON(cryptoKey, e)));
      enterApp();
    } catch (err) {
      lockError.textContent = "Incorrect passphrase. Please try again.";
    }
  }

  function enterApp() {
    lockScreen.classList.add("hidden");
    sbApp.classList.remove("hidden");
    passphraseInput.value = "";
    renderEntries();
  }

  function lockApp() {
    cryptoKey = null;
    vaultSalt = null;
    entries = [];
    sbApp.classList.add("hidden");
    lockScreen.classList.remove("hidden");
    setLockMode();
  }

  async function persistEntries() {
    const vault = getVault();
    const encryptedEntries = await Promise.all(entries.map(e => encryptJSON(cryptoKey, e)));
    saveVault({ salt: vault.salt, check: vault.check, entries: encryptedEntries });
  }

  function renderEntries() {
    entryCount.textContent = entries.length;
    entriesList.innerHTML = "";
    if (entries.length === 0) {
      entriesList.appendChild(emptyState);
      return;
    }
    const sorted = [...entries].sort((a, b) => (b.date || "").localeCompare(a.date || "") || b.createdAt - a.createdAt);
    sorted.forEach(entry => {
      const card = document.createElement("div");
      card.className = "entry-card";
      card.innerHTML = `
        <div class="entry-card-top">
          <div>
            <div class="entry-category">${escapeHTML(entry.category)}</div>
            <div class="entry-date">${escapeHTML(entry.date)}</div>
          </div>
          <button class="entry-delete" title="Delete entry"><i class="fas fa-trash"></i></button>
        </div>
        ${entry.location ? `<div class="entry-meta"><i class="fas fa-location-dot"></i> ${escapeHTML(entry.location)}</div>` : ""}
        ${entry.witness ? `<div class="entry-meta"><i class="fas fa-user-group"></i> Witness: ${escapeHTML(entry.witness)}</div>` : ""}
        <p class="entry-desc">${escapeHTML(entry.description)}</p>
      `;
      card.querySelector(".entry-delete").addEventListener("click", async () => {
        if (!confirm("Delete this entry permanently?")) return;
        entries = entries.filter(e => e.id !== entry.id);
        await persistEntries();
        renderEntries();
      });
      entriesList.appendChild(card);
    });
  }

  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
  }

  entryForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const entry = {
      id: crypto.randomUUID(),
      date: document.getElementById("entryDate").value,
      category: document.getElementById("entryCategory").value,
      location: document.getElementById("entryLocation").value.trim(),
      witness: document.getElementById("entryWitness").value.trim(),
      description: document.getElementById("entryDescription").value.trim(),
      createdAt: Date.now()
    };
    entries.push(entry);
    await persistEntries();
    renderEntries();
    entryForm.reset();
  });

  exportBtn.addEventListener("click", () => {
    const vault = getVault();
    if (!vault) return;
    const blob = new Blob([JSON.stringify(vault, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `safebond-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  importFile.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const imported = JSON.parse(text);
      if (!imported.salt || !imported.check || !Array.isArray(imported.entries)) {
        throw new Error("Invalid backup file.");
      }
      if (!confirm("Importing will replace your current vault on this device. Continue?")) return;
      saveVault(imported);
      alert("Backup imported. Please unlock with the passphrase used for that backup.");
      lockApp();
    } catch (err) {
      alert("Could not import this file — it may not be a valid SafeBond backup.");
    }
    importFile.value = "";
  });

  resetBtn.addEventListener("click", () => {
    if (!confirm("This will permanently erase all SafeBond entries on this device. This cannot be undone. Continue?")) return;
    localStorage.removeItem(STORAGE_KEY);
    lockApp();
  });

  unlockBtn.addEventListener("click", handleUnlock);
  passphraseInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleUnlock();
  });
  lockAgainBtn.addEventListener("click", lockApp);

  document.getElementById("entryDate").valueAsDate = new Date();
  setLockMode();
})();