/* Local scout. Runs in the browser. DNS uses Cloudflare's public resolver.
   It does not exploit, guess passwords, or continue after a private address. */
(function (root) {
  const DOH = "https://cloudflare-dns.com/dns-query";

  async function scout(input) {
    const host = parseHost(input);
    const createdAt = new Date().toISOString();
    const findings = [];
    const passes = [];
    const reach = [];
    scoreName(host, findings, passes);
    const resolved = await resolvePublic(host);
    if (resolved.ips.length === 0) {
      if (resolved.cname && takeoverTarget(resolved.cname)) {
        findings.push(finding(
          "Name points at a hosting address that does not answer",
          "extreme",
          "DNS",
          host + " points at " + resolved.cname + ", and that name has no address.",
          "Remove the alias, or claim it on the host you meant. An abandoned alias can be taken by someone else.",
        ));
      } else {
        findings.push(finding(
          "Host did not resolve",
          "extreme",
          "DNS",
          host + " returned no public address.",
          "Check the spelling and that public DNS is published.",
        ));
      }
    } else {
      reach.push({ step: "DNS", result: resolved.ips.join(", ") });
      if (resolved.ad) passes.push("DNSSEC validated the address lookup.");
      else findings.push(finding("DNSSEC did not validate this lookup", "low", "DNS", "The resolver did not mark the answer as authenticated.", "Sign the zone with DNSSEC so a forged answer is easier to reject."));
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
    const mail = await readDns(apex);
    scoreDns(mail, findings, passes, reach);
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
    let cname = "";
    let ad = false;
    for (let hop = 0; hop < 4; hop += 1) {
      const [v4, v6] = await Promise.all([doh(name, "A"), doh(name, "AAAA")]);
      if (v4.AD || v6.AD) ad = true;
      ips.push(...records(v4, 1), ...records(v6, 28));
      if (ips.length) break;
      const next = (records(v4, 5)[0] || records(v6, 5)[0] || "").replace(/\.$/, "");
      if (!next || next === name) break;
      cname = next;
      name = next;
    }
    if (ips.some(isPrivate)) throw new Error("Shadow Owl stopped. That name points at a private or local address.");
    return { ips, cname, ad };
  }

  async function readDns(apex) {
    const [mxPacket, txtPacket, dmarcPacket, caaPacket, nsPacket] = await Promise.all([
      doh(apex, "MX"),
      doh(apex, "TXT"),
      doh("_dmarc." + apex, "TXT"),
      doh(apex, "CAA"),
      doh(apex, "NS"),
    ]);
    const txt = records(txtPacket, 16).map(unquoteTxt);
    const dmarcTxt = records(dmarcPacket, 16).map(unquoteTxt);
    const mx = records(mxPacket, 15).filter((row) => !/^0\s+\.?$/.test(row.trim()));
    return {
      mx: mx.length ? "present" : "absent",
      mxRows: mx,
      spf: txt.filter((record) => record.toLowerCase().startsWith("v=spf1")),
      dmarc: dmarcTxt.find((record) => record.toLowerCase().includes("v=dmarc1")) || "",
      caa: records(caaPacket, 257),
      ns: records(nsPacket, 2),
    };
  }

  function scoreDns(dns, findings, passes, reach) {
    reach.push({ step: "NS", result: dns.ns.length ? dns.ns.length + " name servers" : "None" });
    if (dns.ns.length === 0) {
      findings.push(finding("No name servers were visible", "low", "DNS", "The NS lookup returned nothing.", "Publish at least two name servers so one outage does not hide the name."));
    } else if (dns.ns.length === 1) {
      findings.push(finding("Only one name server is published", "low", "DNS", dns.ns[0], "Add a second name server on a different network."));
    } else passes.push(dns.ns.length + " name servers are published.");
  }

  function scoreMail(mail, findings, passes, reach) {
    reach.push({ step: "MX", result: mail.mx === "present" ? "Mail exchange is published" : "No mail exchange" });
    reach.push({ step: "SPF", result: mail.spf.join(" | ") || "None" });
    reach.push({ step: "DMARC", result: mail.dmarc || "None" });
    reach.push({ step: "CAA", result: mail.caa[0] || "None" });
    if (mail.mx === "present" || mail.spf.length) scoreMailbox(mail, findings, passes);
    else passes.push("No mail exchange was published, so mailbox spoofing was not scored.");
    if (mail.caa.length === 0) findings.push(finding("No CAA record", "low", "DNS", "No CAA records.", "Publish a CAA record for the authority you use, so other authorities cannot issue a certificate."));
    else if (!mail.caa.some((row) => /\bissue\b/i.test(row))) {
      findings.push(finding("CAA does not name an issuing authority", "low", "DNS", mail.caa.join(" | "), "Add a CAA issue tag for the authority that should mint certificates."));
    } else passes.push("CAA records limit which authorities can issue certificates.");
  }

  function scoreMailbox(mail, findings, passes) {
    if (mail.spf.length > 1) {
      findings.push(finding("More than one SPF record", "mild", "Mail", mail.spf.join(" | "), "Keep a single SPF TXT record. Extra ones can make receivers ignore all of them."));
    }
    const spf = mail.spf[0] || "";
    if (!spf) {
      findings.push(finding("No SPF record", "mild", "Mail", "No v=spf1 TXT record.", "Publish one SPF TXT record ending in -all."));
    } else if (/(?:^|\s)\+all\b/i.test(spf)) {
      findings.push(finding("SPF allows the entire internet to send as you", "extreme", "Mail", spf, "Replace +all with -all after every real sender is listed."));
    } else if (/(?:^|\s)[~?]all\b/i.test(spf)) {
      findings.push(finding("SPF does not hard-fail forgeries", "mild", "Mail", spf, "Move to -all once every real sender is listed."));
    } else if (/(?:^|\s)-all\b/i.test(spf)) passes.push("SPF ends in -all.");
    else if (/redirect=/i.test(spf)) {
      findings.push(finding("SPF redirects and was not fully checked", "low", "Mail", spf, "Open the redirect target and make sure that record ends in -all."));
    } else {
      findings.push(finding("SPF has no final all term", "mild", "Mail", spf, "End the record with -all so unlisted senders fail."));
    }
    if (!mail.dmarc) {
      findings.push(finding("No DMARC policy", "mild", "Mail", "No _dmarc TXT record.", "Publish v=DMARC1; p=quarantine; rua=mailto:you@yourdomain."));
    } else {
      if (/p=none/i.test(mail.dmarc)) findings.push(finding("DMARC is monitor-only", "low", "Mail", mail.dmarc, "Change p=none to p=quarantine, then p=reject."));
      else if (/p=(quarantine|reject)/i.test(mail.dmarc)) passes.push("DMARC is enforcing.");
      const pct = mail.dmarc.match(/pct=(\d+)/i);
      if (pct && Number(pct[1]) < 100) {
        findings.push(finding("DMARC covers only part of the mail", "low", "Mail", mail.dmarc, "Raise pct to 100 so the policy applies to every message."));
      }
      if (!/rua=/i.test(mail.dmarc)) {
        findings.push(finding("DMARC sends no reports", "low", "Mail", mail.dmarc, "Add rua=mailto:you@yourdomain so forgeries show up in a report."));
      }
      if (/aspf=r/i.test(mail.dmarc) || /adkim=r/i.test(mail.dmarc)) {
        findings.push(finding("DMARC alignment is relaxed", "low", "Mail", mail.dmarc, "Use aspf=s and adkim=s so a cousin domain cannot pass as you."));
      }
    }
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
      ? " This ran in your browser. Name tricks, DNS, mail policy, and HTTPS trust were checked."
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

  const BRANDS = [
    ["Facebook", "facebook", ["facebook.com", "fb.com"]],
    ["Instagram", "instagram", ["instagram.com"]],
    ["WhatsApp", "whatsapp", ["whatsapp.com"]],
    ["Google", "google", ["google.com", "google.co.in", "googleusercontent.com", "gstatic.com", "googleapis.com", "googlevideo.com", "withgoogle.com"]],
    ["YouTube", "youtube", ["youtube.com", "youtu.be"]],
    ["Microsoft", "microsoft", ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "windows.com", "azure.com"]],
    ["Apple", "apple", ["apple.com", "icloud.com"]],
    ["Amazon", "amazon", ["amazon.com", "amazon.in", "amazonaws.com", "media-amazon.com"]],
    ["PayPal", "paypal", ["paypal.com"]],
    ["Netflix", "netflix", ["netflix.com"]],
    ["LinkedIn", "linkedin", ["linkedin.com"]],
    ["Adobe", "adobe", ["adobe.com"]],
    ["Dropbox", "dropbox", ["dropbox.com"]],
    ["GitHub", "github", ["github.com", "github.io", "githubusercontent.com", "githubassets.com", "github.dev"]],
    ["Steam", "steampowered", ["steampowered.com"]],
    ["Binance", "binance", ["binance.com"]],
    ["Coinbase", "coinbase", ["coinbase.com"]],
    ["Paytm", "paytm", ["paytm.com"]],
    ["PhonePe", "phonepe", ["phonepe.com"]],
    ["IRCTC", "irctc", ["irctc.co.in"]],
    ["HDFC Bank", "hdfcbank", ["hdfcbank.com"]],
    ["ICICI Bank", "icicibank", ["icicibank.com"]],
  ];
  const LURES = ["login", "logon", "signin", "signon", "secure", "security", "verify", "verification", "account", "update", "support", "wallet", "banking", "password", "recover", "unlock", "billing", "payment", "confirm", "alert"];
  const MULTI_SUFFIX = ["co.in", "com.au", "co.uk", "com.br", "co.jp", "co.za", "com.sg", "com.hk", "co.nz", "com.tr", "co.kr", "com.mx"];
  const TAKEOVER = ["github.io", "herokuapp.com", "azurewebsites.net", "cloudapp.net", "s3.amazonaws.com", "cloudfront.net", "ghost.io", "myshopify.com", "zendesk.com", "readme.io", "surge.sh", "bitbucket.io", "pantheonsite.io", "netlify.app", "vercel.app", "firebaseapp.com", "web.app", "appspot.com"];

  function scoreName(host, findings, passes) {
    if (host.split(".").some((label) => label.startsWith("xn--"))) {
      findings.push(finding("Name uses punycode", "mild", "Name", host, "Punycode can imitate a real brand with another alphabet. Open it only if you already know the owner."));
    }
    const hit = lookalike(host);
    if (hit) {
      findings.push(finding(
        "Name imitates " + hit.brand,
        "extreme",
        "Name",
        hit.evidence,
        "Do not type a password or a payment here. The real site is " + hit.official + ".",
      ));
      return;
    }
    const owned = ownedBrand(host);
    if (owned) passes.push("This name is the real " + owned[0] + " domain, not a lookalike.");
  }

  function lookalike(host) {
    if (ownedBrand(host)) return null;
    const labels = host.split(".");
    const stem = registrableLabel(host);
    const folded = labels.map(skeleton);
    for (const [brand, token, domains] of BRANDS) {
      const brandFold = skeleton(token);
      if (brandFold.length < 5) continue;
      for (const label of folded) {
        if (!label) continue;
        if (label === brandFold) {
          return { brand, official: domains[0], evidence: host + " copies " + brand + " but it is not " + domains[0] + "." };
        }
        if (brandFold.length >= 6 && label.length >= brandFold.length && editDistance(label, brandFold) === 1) {
          return { brand, official: domains[0], evidence: host + " is one small change away from " + brand + "." };
        }
        if (label.includes(brandFold) && label !== brandFold && lureOrShortExtra(label, brandFold)) {
          return { brand, official: domains[0], evidence: host + " hides " + brand + " inside another name." };
        }
      }
      if (skeleton(stem) !== skeleton(token) && folded.some((label) => label === brandFold)) {
        return { brand, official: domains[0], evidence: host + " puts " + brand + " in front of a different domain." };
      }
    }
    return null;
  }

  function ownedBrand(host) {
    const last = host.split(".").pop();
    return BRANDS.find((brand) => last === brand[1] || isOfficial(host, brand[2])) || null;
  }

  function isOfficial(host, domains) {
    return domains.some((domain) => host === domain || host.endsWith("." + domain));
  }

  function registrableLabel(host) {
    const labels = host.split(".");
    const tail = labels.slice(-2).join(".");
    if (MULTI_SUFFIX.includes(tail) && labels.length >= 3) return labels[labels.length - 3];
    return labels[labels.length - 2] || host;
  }

  function skeleton(value) {
    return String(value).toLowerCase().replace(/[^a-z0-9]/g, "").replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/rn/g, "m");
  }

  function lureOrShortExtra(label, brandFold) {
    const extra = label.replace(brandFold, "");
    if (!extra) return false;
    if (extra.length <= 3) return true;
    return LURES.some((lure) => extra === lure || extra.startsWith(lure) || extra.endsWith(lure));
  }

  function editDistance(left, right) {
    const row = [];
    for (let j = 0; j <= right.length; j += 1) row[j] = j;
    for (let i = 1; i <= left.length; i += 1) {
      let previous = row[0];
      row[0] = i;
      for (let j = 1; j <= right.length; j += 1) {
        const saved = row[j];
        const cost = left[i - 1] === right[j - 1] ? 0 : 1;
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + cost);
        previous = saved;
      }
    }
    return row[right.length];
  }

  function takeoverTarget(name) {
    const host = name.toLowerCase().replace(/\.$/, "");
    return TAKEOVER.some((suffix) => host === suffix || host.endsWith("." + suffix));
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
