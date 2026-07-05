"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;

function send(msg) {
  return new Promise((resolve) => api.runtime.sendMessage(msg, resolve));
}

const boxes = document.querySelectorAll("input[data-key]");
const saved = document.getElementById("saved");
let savedTimer;

async function init() {
  const state = await send({ type: "get-state" });
  for (const box of boxes) {
    box.checked = state.settings[box.dataset.key] !== false;
    box.addEventListener("change", async () => {
      await send({ type: "set-settings", settings: { [box.dataset.key]: box.checked } });
      saved.hidden = false;
      clearTimeout(savedTimer);
      savedTimer = setTimeout(() => (saved.hidden = true), 1500);
    });
  }
}

init();
