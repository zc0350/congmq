// Drives the running congmq broker with mqtt.js — a third-party client — to
// check that the rule files in ../rules behave as their comments claim.
//
//	bin/congmq.exe -addr :1883 -auth rules/auth.jsonl -acl rules/acl.jsonl
//	node test/rules-check.mjs
//
// CONGMQ_PORT points it at a broker on another port, which is how the same
// checks are run against a freshly built binary without disturbing a dev
// broker that is already holding 1883.
import mqtt from "mqtt";
import crypto from "node:crypto";

const hex = (alg, s) => crypto.createHash(alg).update(s, "utf8").digest("hex");
// The rule files hash the username with everything outside [A-Za-z0-9]
// removed, which is what "sanitize" means there.
const sanitize = (u) => u.replace(/[^A-Za-z0-9]/g, "");

const PORT = Number(process.env.CONGMQ_PORT ?? 1883);
const V4 = `mqtt://127.0.0.1:${PORT}`;
const V6 = `mqtt://[::1]:${PORT}`;

const password = {
  // {"username":"dashboard", salt:"c0ng-2026", alg:"sha256", scheme:"salt+username"}
  dashboard: hex("sha256", "c0ng-2026" + "dashboard"),
  // {"username":"^aaaa_[a-z0-9]+$", salt:"d3v1c3", alg:"md5", scheme:"username+salt"}
  device: hex("md5", sanitize("aaaa_abcde") + "d3v1c3"),
};

let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures++;
};

function connect(url, { clientId, username, password: secret }) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(url, {
      clientId,
      username,
      password: secret,
      reconnectPeriod: 0,
      connectTimeout: 5000,
      clean: true,
    });
    const timer = setTimeout(() => {
      client.end(true);
      reject(new Error("connect timed out"));
    }, 8000);
    client.once("connect", () => {
      clearTimeout(timer);
      resolve(client);
    });
    client.once("error", (err) => {
      clearTimeout(timer);
      client.end(true);
      reject(err);
    });
  });
}

const subscribe = (client, topic, qos = 1) =>
  new Promise((resolve, reject) =>
    client.subscribe(topic, { qos }, (err, granted) => (err ? reject(err) : resolve(granted))),
  );

const publish = (client, topic, payload, qos = 1) =>
  new Promise((resolve, reject) =>
    client.publish(topic, payload, { qos }, (err) => (err ? reject(err) : resolve())),
  );

// oneMessage resolves with the next message on any of the client's open
// subscriptions, or rejects after the wait so a "must not arrive" case is a
// decision rather than a pause.
function oneMessage(client, waitMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      client.off("message", handler);
      reject(new Error("nothing arrived"));
    }, waitMs);
    function handler(topic, payload) {
      clearTimeout(timer);
      client.off("message", handler);
      resolve({ topic, payload: payload.toString() });
    }
    client.on("message", handler);
  });
}

const close = (client) => new Promise((resolve) => client.end(true, resolve));

async function refused(label, url, creds, wantCode) {
  try {
    const client = await connect(url, creds);
    check(label, false, "the broker accepted it");
    await close(client);
  } catch (err) {
    check(label, err.code === wantCode, `code ${err.code}: ${err.message}`);
  }
}

async function main() {
  console.log(`credentials: dashboard=${password.dashboard.slice(0, 12)}… device=${password.device}\n`);

  // --- auth.jsonl ---
  const dash = await connect(V4, { clientId: "ops-1", username: "dashboard", password: password.dashboard });
  check("dashboard connects on its sha256(salt+username) digest", dash.connected);

  const dev = await connect(V4, { clientId: "dev-aaaa", username: "aaaa_abcde", password: password.device });
  check("device connects on md5(sanitized username+salt)", dev.connected);

  await refused("a wrong password is refused", V4, { clientId: "bad-1", username: "dashboard", password: "deadbeef" }, 4);
  await refused("an account no rule describes is refused", V4, { clientId: "bad-2", username: "nobody", password: password.device }, 4);
  await refused("no credentials at all is refused", V4, { clientId: "bad-3", username: "", password: "" }, 4);

  // --- acl.jsonl, both directions on the product channel ---
  const grantedCmd = await subscribe(dev, "abcde/aaaa/cmd", 1).catch(() => null);
  check("device may subscribe its own cmd channel", Array.isArray(grantedCmd) && grantedCmd.length === 1,
    grantedCmd ? JSON.stringify(grantedCmd) : "the subscribe was refused");

  // The listener goes on before the publish: on a broker that delivers in the same
  // read, the message has already been emitted by the time the PUBACK resolves,
  // and attaching afterwards loses it.
  const cmdSeen = oneMessage(dev, 4000);
  await publish(dash, "abcde/aaaa/cmd", "reboot");
  const cmd = await cmdSeen;
  check("command reaches the device", cmd.topic === "abcde/aaaa/cmd" && cmd.payload === "reboot", `${cmd.topic}=${cmd.payload}`);

  const evtSeen = oneMessage(dash, 4000);
  await subscribe(dash, "abcde/#", 1);
  await publish(dev, "abcde/aaaa/event", '{"temp":21}');
  const evt = await evtSeen;
  check("device event reaches the cloud side", evt.topic === "abcde/aaaa/event", evt.topic);

  // --- the ip constraint, and file order: deny before the catch-all allow ---
  // 127.0.0.1 is granted "all" on "#" by rule 2, so a broad subscription works
  // there. The same client arriving on ::1 is not covered by that rule, so the
  // explicit deny of "#" (written as {"eq": "#"} so the two characters are
  // compared literally) decides first, and only then would the catch-all.
  const wide = await connect(V4, { clientId: "wide-4", username: "aaaa_abcde", password: password.device });
  const grantedV4 = await subscribe(wide, "#", 0).then(() => true).catch(() => false);
  check("from 127.0.0.1 the ip rule grants \"#\"", grantedV4);
  await close(wide);

  const v6 = await connect(V6, { clientId: "wide-6", username: "aaaa_abcde", password: password.device });
  check("device connects over ipv6 loopback too", v6.connected);
  const denied = await subscribe(v6, "#", 0).then(() => null).catch((err) => err);
  check("from ::1 the deny rule refuses \"#\"", denied !== null && denied !== undefined,
    denied ? `code ${denied.code}: ${denied.message}` : "it was granted");
  await close(v6);

  await close(dev);
  await close(dash);
}

// A hung client would otherwise keep the process alive with no output.
const watchdog = setTimeout(() => {
  console.error("\nFAIL  the run exceeded 60s and was aborted");
  process.exit(1);
}, 60000);

main()
  .then(async () => {
    clearTimeout(watchdog);
    console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
    process.exitCode = failures ? 1 : 0;
  })
  .catch(async (err) => {
    clearTimeout(watchdog);
    console.error("\nFAIL", err);
    process.exitCode = 1;
  })
  .finally(() => process.exit(process.exitCode ?? 1));
