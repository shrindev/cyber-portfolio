/* Local scout. Runs in the browser. DNS uses Cloudflare's public resolver.
   It does not exploit, guess passwords, or continue after a private address. */
(function (root) {
  const DOH = "https://cloudflare-dns.com/dns-query";

  async function scout(input) {
    const host = parseHost(input);
    const createdAt = new Date().toISOString();
    const ips = await resolvePublic(host);
    const findings = [];
    const passes = [];
    const reach = [];
    if (ips.length === 0) {
      findings.push(finding(
        "Host did not resolve",
        "extreme",
        "DNS",
        host + " returned no public address.",
        "Check the spelling and that public DNS is published.",
      ));
    } else {
      reach.push({ step: "DNS", result: ips.join(", ") });
      const httpsOk = await httpsOpens(host);
      reach.push({ step: "HTTPS", result: httpsOk ? "This browser opened it" : "This browser could not open it" });
      if (!httpsOk) {
        findings.push(finding(
          "This browser could not open HTTPS",
          "extreme",
          "Transport",
          "https://" + host + " did not open from this browser.",
          "Serve a publicly trusted certificate on port 443. If the site is up, a bad name or an expired certificate will look like this.",
        ));
      } else {
        passes.push("This browser opened HTTPS and trusted the certificate.");
      }
    }
    const apex = host.startsWith("www.") ? host.slice(4) : host;
    const mail = await readMail(apex);
    scoreMail(mail, findings, passes, reach);
    return finish(host, createdAt, findings, passes, reach, "local");
  }

  async function scoutBrowser() {
    const findings = [];
    const passes = [];
    if (typeof window !== "undefined" && window.isSecureContext) passes.push("This page is a secure context.");
    else findings.push(finding("This page is not a secure context", "extreme", "Device", location.protocol, "Open this page over HTTPS."));
    const leaked = await ice();
    if (leaked.length) {
      findings.push(finding(
        "This browser can reveal a private address",
        "mild",
        "Device",
        leaked.join(", "),
        "Prefer a browser that hides local addresses behind mDNS hostnames.",
      ));
    } else passes.push("No private address leaked through WebRTC.");
    const report = finish("This browser", new Date().toISOString(), findings, passes, [], "device");
    report.summary = "This browser was checked on this device. Nothing about a remote host was scanned.";
    return report;
  }

  function parseHost(input) {
    const raw = String(input || "").trim();
    if (!raw) throw new Error("Enter a public host or URL.");
    if (raw.length > 300) throw new Error("That target is too long.");
    let host = raw;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
      let url;
      try { url = new URL(raw); }
      catch { throw new Error("That URL could not be read."); }
      if (url.username || url.password) throw new Error("Remove any username or password from the URL.");
      if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only http and https URLs are accepted.");
      host = url.hostname;
    } else {
      host = raw.split("/")[0].split("?")[0].split("#")[0];
      if (host.includes("@")) throw new Error("Remove any username from the target.");
      host = host.replace(/:\d+$/, "");
    }
    host = host.toLowerCase().replace(/\.$/, "");
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
    if (isIp(host)) throw new Error("IP targets are blocked. Use a public hostname.");
    if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..") || host.startsWith("-") || host.endsWith("-") || host.startsWith(".") || host.endsWith(".")) {
      throw new Error("Use a plain public hostname, like example.com.");
    }
    const blocked = host === "localhost" || [".local", ".internal", ".localhost", ".lan", ".localdomain", ".home", ".arpa"].some((suffix) => host.endsWith(suffix));
    if (blocked || host.split(".").length < 2) throw new Error("That name is local or not a public hostname.");
    return host;
  }

  async function resolvePublic(host) {
    let name = host;
    const ips = [];
    for (let hop = 0; hop < 4; hop += 1) {
      const [v4, v6] = await Promise.all([doh(name, "A"), doh(name, "AAAA")]);
      ips.push(...records(v4, 1), ...records(v6, 28));
      if (ips.length) break;
      const cname = (records(v4, 5)[0] || records(v6, 5)[0] || "").replace(/\.$/, "");
      if (!cname || cname === name) break;
      name = cname;
    }
    if (ips.some(isPrivate)) throw new Error("Shadow Owl stopped. That name points at a private or local address.");
    return ips;
  }

  async function readMail(apex) {
    const [mxPacket, txtPacket, dmarcPacket, caaPacket] = await Promise.all([
      doh(apex, "MX"),
      doh(apex, "TXT"),
      doh("_dmarc." + apex, "TXT"),
      doh(apex, "CAA"),
    ]);
    const txt = records(txtPacket, 16).map(unquoteTxt);
    const dmarcTxt = records(dmarcPacket, 16).map(unquoteTxt);
    return {
      mx: records(mxPacket, 15).length ? "present" : "absent",
      spf: txt.filter((record) => record.toLowerCase().startsWith("v=spf1")),
      dmarc: dmarcTxt.find((record) => record.toLowerCase().includes("v=dmarc1")) || "",
      caa: records(caaPacket, 257),
    };
  }

  function scoreMail(mail, findings, passes, reach) {
    reach.push({ step: "MX", result: mail.mx === "present" ? "Mail exchange is published" : "No mail exchange" });
    reach.push({ step: "SPF", result: mail.spf[0] || "None" });
    reach.push({ step: "DMARC", result: mail.dmarc || "None" });
    reach.push({ step: "CAA", result: mail.caa[0] || "None" });
    if (mail.mx === "absent" && mail.spf.length === 0) {
      passes.push("No mail exchange was published, so mailbox spoofing was not scored.");
      return;
    }
    if (mail.spf.length === 0) {
      findings.push(finding("No SPF record", "mild", "Mail", "No v=spf1 TXT record.", "Publish one SPF TXT record ending in -all or, while testing, ~all."));
    } else if (/(?:^|\s)\+?all\b/i.test(mail.spf[0]) && !/(?:^|\s)[~?-]all\b/i.test(mail.spf[0])) {
      findings.push(finding("SPF allows the entire internet to send as you", "extreme", "Mail", mail.spf[0], "Replace +all with -all after every real sender is listed."));
    } else if (/(?:^|\s)[~?]all\b/i.test(mail.spf[0])) {
      findings.push(finding("SPF does not hard-fail forgeries", "mild", "Mail", mail.spf[0], "Move to -all once every real sender is listed."));
    } else if (/(?:^|\s)-all\b/i.test(mail.spf[0])) passes.push("SPF ends in -all.");
    if (!mail.dmarc) findings.push(finding("No DMARC policy", "mild", "Mail", "No _dmarc TXT record.", "Publish v=DMARC1; p=quarantine; rua=mailto:you@yourdomain."));
    else if (/p=none/i.test(mail.dmarc)) findings.push(finding("DMARC is monitor-only", "low", "Mail", mail.dmarc, "Change p=none to p=quarantine, then p=reject."));
    else if (/p=(quarantine|reject)/i.test(mail.dmarc)) passes.push("DMARC is enforcing.");
    if (mail.caa.length === 0) findings.push(finding("No CAA record", "low", "DNS", "No CAA records.", "Publish a CAA record for the authority you use, so other authorities cannot issue a certificate."));
    else passes.push("CAA records limit which authorities can issue certificates.");
  }

  async function doh(name, type) {
    const response = await fetch(DOH + "?name=" + encodeURIComponent(name) + "&type=" + type, {
      headers: { accept: "application/dns-json" },
    });
    if (!response.ok) throw new Error("DNS lookup failed. Try again in a moment.");
    const packet = await response.json();
    if (packet.Status && packet.Status !== 0 && packet.Status !== 3) throw new Error("DNS lookup failed. Try again in a moment.");
    return packet;
  }

  function records(packet, type) {
    return (packet.Answer || []).filter((row) => row.type === type).map((row) => String(row.data));
  }

  function unquoteTxt(data) {
    const parts = [];
    const pattern = /"((?:\\.|[^"\\])*)"/g;
    let match;
    while ((match = pattern.exec(data))) parts.push(match[1].replace(/\\(.)/g, "$1"));
    return parts.length ? parts.join("") : data;
  }

  async function httpsOpens(host) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);
    try {
      await fetch("https://" + host + "/", { mode: "no-cors", cache: "no-store", signal: controller.signal });
      return true;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  function ice() {
    return new Promise((resolve) => {
      if (typeof RTCPeerConnection === "undefined") {
        resolve([]);
        return;
      }
      const ips = new Set();
      let pc;
      try { pc = new RTCPeerConnection({ iceServers: [] }); }
      catch { resolve([]); return; }
      const done = () => {
        try { pc.close(); } catch (e) { /* already closed */ }
        resolve([...ips].filter(isPrivate));
      };
      const timer = setTimeout(done, 2000);
      pc.onicecandidate = (event) => {
        if (!event.candidate) {
          clearTimeout(timer);
          done();
          return;
        }
        const match = event.candidate.candidate.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
        if (match) ips.add(match[1]);
      };
      pc.createDataChannel("owl");
      pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(done);
    });
  }

  function finish(host, createdAt, findings, passes, reach, mode) {
    const rank = { extreme: 0, mild: 1, low: 2 };
    findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
    let score = 100;
    for (const item of findings) score -= item.severity === "extreme" ? 18 : item.severity === "mild" ? 8 : 3;
    score = Math.max(0, Math.min(100, score));
    const posture = score >= 85 ? "Hold" : score >= 65 ? "Watch" : score >= 40 ? "Exposed" : "Critical";
    const extreme = findings.filter((item) => item.severity === "extreme").length;
    const mild = findings.filter((item) => item.severity === "mild").length;
    const low = findings.filter((item) => item.severity === "low").length;
    const where = mode === "local"
      ? " This ran in your browser. DNS, mail policy, and HTTPS trust were checked."
      : "";
    return {
      createdAt,
      target: host,
      mode,
      score,
      posture,
      summary: host + " is " + posture.toLowerCase() + " at " + score + ". " + extreme + " extreme, " + mild + " mild, " + low + " low." + where,
      findings,
      passes,
      reach,
    };
  }

  function finding(title, severity, area, evidence, fix) {
    return { title, severity, area, evidence, why: evidence, fix: [fix] };
  }

  function isIp(value) {
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return true;
    return value.includes(":");
  }

  function isPrivate(ip) {
    const lower = ip.toLowerCase();
    if (lower.startsWith("::ffff:")) return isPrivate(lower.slice(7));
    if (lower.includes(":")) {
      return lower === "::1" || lower === "::" || lower.startsWith("fc") || lower.startsWith("fd") || /^fe[89ab]/.test(lower);
    }
    const parts = lower.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => Number.isNaN(part) || part > 255)) return true;
    const a = parts[0];
    const b = parts[1];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && (b === 168 || b === 0)) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return a >= 224;
  }

  const api = { scout, scoutBrowser, parseHost };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ShadowOwl = api;
})(typeof window !== "undefined" ? window : globalThis);
