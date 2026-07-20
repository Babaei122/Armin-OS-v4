import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const worker = await readFile(new URL("../service-worker.js", import.meta.url), "utf8");
const manifest = JSON.parse(await readFile(new URL("../manifest.webmanifest", import.meta.url), "utf8"));

const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
assert.equal(new Set(ids).size, ids.length, "HTML must not contain duplicate ids");

for (const match of html.matchAll(/<label[^>]*\sfor="([^"]+)"[^>]*>/g)) {
  assert(ids.includes(match[1]), `label target #${match[1]} must exist`);
}
for (const match of html.matchAll(/<dialog[^>]*\saria-labelledby="([^"]+)"[^>]*>/g)) {
  assert(ids.includes(match[1]), `dialog label #${match[1]} must exist`);
}

const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map((match) => match[1]).filter((source) => source.trim());
assert(inlineScripts.length > 0, "main inline script must exist");
for (const source of inlineScripts) new Function(source);
new Function(worker);

assert.equal(manifest.lang, "fa");
assert.equal(manifest.dir, "rtl");
assert(manifest.icons?.some((icon) => icon.sizes === "192x192"));
assert(manifest.icons?.some((icon) => icon.sizes === "512x512"));
assert(worker.includes("planos-pwa-v7"), "service worker cache version must be current");
assert(html.includes("@tabler/icons-webfont"), "professional Tabler icon library must be wired");
assert(html.includes("daily-insight-orbit.png"), "daily insight artwork must be wired");
assert(html.includes("planos-orbit-mark.png"), "orbit brand mark must be wired");
assert(html.includes("daily-insight-orbit-dark.png"), "dark insight artwork must be wired");
assert(html.includes("daily-insight-orbit-mobile.png"), "mobile insight artwork must be wired");
assert(html.includes("daily-insight-orbit-mobile-dark.png"), "mobile dark insight artwork must be wired");
assert(html.includes("renderReminderCenter"), "in-app reminder center must be available");
assert(html.includes("toLocaleString(\"en-US\")"), "rendered numbers must use English digits");
assert(html.includes("sanitizeImportedState"), "imports must be sanitized");
assert(html.includes("PBKDF2"), "PIN hashing must use a slow KDF");
assert(html.includes("taskReminderEnabled"), "task reminders must be available");
assert(html.includes("DISCIPLINE_QUOTES"), "daily discipline quotes must be available");
assert(html.includes("mobile-nav"), "mobile navigation must be available");
assert(html.includes("weeklyReviews"), "weekly review data must be available");
assert(html.includes("taskProject"), "tasks must support project links");
assert(html.includes("taskGoal"), "tasks must support goal links");
assert(html.includes("plannerInboxList"), "planner inbox must be available");
assert(html.includes("todayCapacity"), "daily capacity planning must be available");
assert(html.includes("btnStartWeeklyReview"), "weekly review flow must be available");

console.log("PlanOS validation passed");
