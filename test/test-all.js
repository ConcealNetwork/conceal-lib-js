import { runCryptoTests } from "./test-crypto.js";
import { runCypherTests } from "./test-cypher.js";
import { runMnemonicTests } from "./test-mnemonic.js";

const SUITES = [
  { name: "mnemonic", run: runMnemonicTests },
  { name: "crypto", run: runCryptoTests },
  { name: "cypher", run: runCypherTests },
];

async function runAll() {
  const container = document.getElementById("results");
  container.innerHTML = "";

  for (const suite of SUITES) {
    const section = document.createElement("section");

    const title = document.createElement("h3");
    title.textContent = suite.name;
    section.appendChild(title);

    const log = (msg, ok) => {
      const p = document.createElement("p");
      p.textContent = (ok ? "✓ " : "✗ ") + msg;
      p.className = ok ? "pass" : "fail";
      section.appendChild(p);
    };

    try {
      await suite.run(log);
    } catch (e) {
      log("suite crashed: " + e, false);
    }

    container.appendChild(section);
  }
}

runAll();
