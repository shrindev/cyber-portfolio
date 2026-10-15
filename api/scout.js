import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

const UA = "ShadowOwl/1.0 (defensive posture scout)";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Use POST." });
    return;
  }
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
    const report = await runScout(String(body.host || ""));
    res.status(200).json(report);
  } catch (error) {
    const message = error instanceof Error ? error.message : "The scout could not finish.";
    res.status(400).json({ error: message });
  }
}

async function runScout(input) {
  const host = parseHost(input);
  const createdAt = new Date().toISOString();
  const addresses = await resolvePublic(host);
  if (addresses.length === 0) {
    return finish(host, createdAt, [
      finding("dns-unresolved", "Host did not resolve", "extreme", "DNS", `${host} returned no public address.`, "Nothing else could be scored.", [
        "Check the spelling and that public DNS is published.",
      ]),
    ], [], [{ step: "DNS", result: "No public address" }]);
  }
  const ip = addresses.find((item) => net.isIP(item) === 4) || addresses[0];
  const [tlsFact, httpsResult, httpResult, mail, securityTxt] = await Promise.all([
    readTls(ip, host),
    readHttps(ip, host).then((value) => ({ ok: true, value }), (error) => ({ ok: false, error: errorText(error) })),
    requestOnce("http", ip, host, "/").then((value) => ({ ok: true, value }), (error) => ({ ok: false, error: errorText(error) })),
    readMail(host.startsWith("www.") ? host.slice(4) : host),
    requestOnce("https", ip, host, "/.well-known/security.txt").then((value) => value.status, () => null),
  ]);
  const findings = [];
  const passes = [];
  const reach = [{ step: "DNS", result: addresses.join(", ") }];
  scoreTls(host, tlsFact, httpsResult, findings, passes, reach);
  if (httpsResult.ok) {
    reach.push({ step: "HTTPS headers", result: `Status ${httpsResult.value.status}` });
    scoreHeaders(httpsResult.value, findings, passes);
    scoreCookies(httpsResult.value.cookies, findings, passes);
  }
  scoreHttp(httpResult, findings, passes, reach);
  scoreMail(mail, findings, passes, reach);
  if (securityTxt === 200) passes.push("security.txt is published.");
  else if (securityTxt != null) {
    findings.push(finding("security-txt", "No security.txt", "low", "Disclosure", `/.well-known/security.txt returned ${securityTxt}.`, "A researcher has no official contact.", [
      "Publish /.well-known/security.txt with a Contact and an Expires date.",
    ]));
  }
  if (securityTxt != null) reach.push({ step: "security.txt", result: String(securityTxt) });
  return finish(host, createdAt, findings, passes, reach);
}

function finish(host, createdAt, findings, passes, reach) {
  const rank = { extreme: 0, mild: 1, low: 2 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
  let score = 100;
  for (const item of findings) score -= item.severity === "extreme" ? 18 : item.severity === "mild" ? 8 : 3;
  score = Math.max(0, Math.min(100, score));
  const posture = score >= 85 ? "Hold" : score >= 65 ? "Watch" : score >= 40 ? "Exposed" : "Critical";
  const extreme = findings.filter((item) => item.severity === "extreme").length;
  const mild = findings.filter((item) => item.severity === "mild").length;
  const low = findings.filter((item) => item.severity === "low").length;
  return {
    id: `${Date.now()}`,
    createdAt,
    target: host,
    mode: "host",
    score,
    posture,
    summary: `${host} is ${posture.toLowerCase()} at ${score}. ${extreme} extreme, ${mild} mild, ${low} low.`,
    findings,
    passes,
    reach,
  };
}

function finding(id, title, severity, area, evidence, why, fix) {
  return { id, title, severity, area, evidence, why, fix };
}

function parseHost(input) {
  const raw = input.trim();
  if (!raw) throw new Error("Enter a public host or URL.");
  if (raw.length > 300) throw new Error("That target is too long.");
  let host = raw;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    const url = new URL(raw);
    if (url.username || url.password) throw new Error("Remove any username or password from the URL.");
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only http and https URLs are accepted.");
    host = url.hostname;
  } else {
    host = raw.split("/")[0].split("?")[0].split("#")[0];
    if (host.includes("@")) throw new Error("Remove any username from the target.");
    host = host.replace(/:\d+$/, "");
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (net.isIP(host)) throw new Error("IP targets are blocked. Use a public hostname.");
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..") || host.startsWith("-") || host.endsWith("-")) {
    throw new Error("Use a plain public hostname, like example.com.");
  }
  const blocked = host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost") || host.endsWith(".lan");
  if (blocked || host.split(".").length < 2) throw new Error("That name is local or not a public hostname.");
  return host;
}

async function resolvePublic(host) {
  let records;
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch (error) {
    const code = error && error.code;
    if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "ENODATA") return [];
    throw new Error("DNS lookup failed. Try again in a moment.");
  }
  if (records.some((record) => isPrivateAddress(record.address))) {
    throw new Error("Shadow Owl stopped. That name points at a private or local address.");
  }
  return records.map((record) => record.address);
}

function isPrivateAddress(ip) {
  const mapped = ip.toLowerCase().startsWith("::ffff:") ? ip.slice(7) : ip;
  if (net.isIP(mapped) === 4) {
    const [a, b] = mapped.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && (b === 168 || b === 0)) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  return lower === "::1" || lower === "::" || lower.startsWith("fc") || lower.startsWith("fd") || /^fe[89ab]/.test(lower);
}

function readTls(ip, host) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, timeout: 6000 }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol() || null;
      const cipher = socket.getCipher()?.name || null;
      const authorized = socket.authorized;
      const authError = socket.authorizationError ? String(socket.authorizationError) : null;
      socket.end();
      if (!cert || !cert.valid_to) {
        resolve(null);
        return;
      }
      const sans = String(cert.subjectaltname || "").split(",").map((part) => part.trim().replace(/^DNS:/i, "")).filter(Boolean);
      const subject = Array.isArray(cert.subject?.CN) ? cert.subject.CN[0] : cert.subject?.CN || "";
      const issuer = cert.issuer?.O || cert.issuer?.CN || "";
      const daysLeft = Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000);
      resolve({
        protocol,
        cipher,
        authorized,
        authError: authorized ? null : authError,
        validTo: cert.valid_to,
        subject,
        issuer: Array.isArray(issuer) ? issuer[0] : issuer,
        sans,
        daysLeft: Number.isNaN(daysLeft) ? null : daysLeft,
        nameOk: nameMatches(host, sans, subject),
      });
    });
    socket.once("error", () => resolve(null));
    socket.setTimeout(6000, () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function nameMatches(host, sans, cn) {
  return [...sans, cn].filter(Boolean).some((name) => {
    const value = String(name).toLowerCase();
    if (value === host) return true;
    if (!value.startsWith("*.")) return false;
    const rest = value.slice(2);
    return host.endsWith(`.${rest}`) && !host.slice(0, host.length - rest.length - 1).includes(".");
  });
}

function scoreTls(host, tlsFact, httpsResult, findings, passes, reach) {
  if (!tlsFact) {
    findings.push(finding("tls-unreachable", "HTTPS on port 443 did not complete", "extreme", "Transport", httpsResult.ok ? "No certificate details." : httpsResult.error, "Without HTTPS, traffic can be read or changed on the path.", [
      "Serve this name on port 443 with a publicly trusted certificate.",
    ]));
    reach.push({ step: "TLS 443", result: httpsResult.ok ? "No certificate" : httpsResult.error });
    return;
  }
  reach.push({ step: "TLS 443", result: `${tlsFact.protocol || "unknown"} · ${tlsFact.cipher || "unknown"} · ${tlsFact.authorized ? "trusted" : "not trusted"}` });
  const expired = tlsFact.daysLeft != null && tlsFact.daysLeft < 0;
  if (expired) {
    findings.push(finding("tls-expired", "Certificate is expired", "extreme", "TLS", `Not after ${tlsFact.validTo}.`, "Browsers warn or block, and people learn to click through.", ["Renew the certificate and install it on this name."]));
  } else if (!tlsFact.authorized) {
    findings.push(finding("tls-untrusted", "Certificate is not publicly trusted", "extreme", "TLS", tlsFact.authError || "Trust check failed.", "A private certificate trains people to ignore warnings.", ["Issue a certificate from a public CA for this hostname."]));
  } else passes.push(`Certificate is trusted, issued by ${tlsFact.issuer || "a public CA"}.`);
  if (!tlsFact.nameOk) {
    findings.push(finding("tls-name", "Certificate name does not match the host", "extreme", "TLS", tlsFact.sans.join(", ") || tlsFact.subject, `${host} is not on the certificate.`, [`Reissue it with ${host} in the subject alternative name.`]));
  } else if (tlsFact.authorized && !expired) passes.push(`Certificate covers ${host}.`);
  if (!expired && tlsFact.daysLeft != null && tlsFact.daysLeft < 14) {
    findings.push(finding("tls-soon", "Certificate expires within 14 days", "extreme", "TLS", `${tlsFact.daysLeft} days left.`, "A missed renewal becomes an outage.", ["Renew now."]));
  } else if (!expired && tlsFact.daysLeft != null && tlsFact.authorized) passes.push(`Certificate has ${tlsFact.daysLeft} days left.`);
  if (tlsFact.protocol === "TLSv1.3") passes.push("TLS 1.3 was negotiated.");
  else if (tlsFact.protocol === "TLSv1.2") findings.push(finding("tls-12", "Session negotiated TLS 1.2", "low", "TLS", "TLSv1.2", "TLS 1.2 is still acceptable. Prefer 1.3.", ["Enable TLS 1.3 on the edge."]));
  else if (tlsFact.protocol) findings.push(finding("tls-old", "Old TLS protocol was negotiated", "extreme", "TLS", tlsFact.protocol, "TLS 1.0 and 1.1 are breakable.", ["Disable TLS 1.0 and 1.1."]));
}

function scoreHeaders(httpFact, findings, passes) {
  const headers = httpFact.headers;
  const csp = headers["content-security-policy"] || "";
  if (!csp && headers["content-security-policy-report-only"]) {
    findings.push(finding("csp-report", "Content Security Policy is report-only", "mild", "Headers", "Report-Only is set.", "It watches violations and does not stop injected script.", ["Move a working policy into Content-Security-Policy."]));
  } else if (!csp) {
    findings.push(finding("csp-missing", "No Content Security Policy", "extreme", "Headers", "Content-Security-Policy was not sent.", "One injected script can ride the user's session.", ["Send Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'."]));
  } else passes.push("A Content Security Policy is being enforced.");
  const hsts = headers["strict-transport-security"];
  if (!hsts) findings.push(finding("hsts-missing", "No Strict-Transport-Security", "extreme", "Headers", "Strict-Transport-Security was not sent.", "The first visit can still be stripped to cleartext.", ["Send Strict-Transport-Security: max-age=31536000; includeSubDomains."]));
  else passes.push("HSTS is present.");
  const framed = /frame-ancestors/i.test(csp) || headers["x-frame-options"];
  if (!framed) findings.push(finding("frame-missing", "Page can be framed by other sites", "mild", "Headers", "No frame control.", "Another site can wrap this page and trick a click.", ["Add frame-ancestors 'self' or X-Frame-Options: DENY."]));
  else passes.push("Clickjacking controls are present.");
  if ((headers["x-content-type-options"] || "").toLowerCase() !== "nosniff") {
    findings.push(finding("nosniff", "MIME sniffing is not disabled", "mild", "Headers", headers["x-content-type-options"] || "Header missing.", "Browsers may treat an uploaded file as script.", ["Send X-Content-Type-Options: nosniff."]));
  } else passes.push("MIME sniffing is disabled.");
  if (!headers["referrer-policy"]) findings.push(finding("referrer", "No Referrer-Policy", "low", "Headers", "Referrer-Policy was not sent.", "Full URLs can leak to other sites.", ["Send Referrer-Policy: strict-origin-when-cross-origin."]));
  if (headers["x-powered-by"]) findings.push(finding("powered-by", "Framework version is advertised", "mild", "Disclosure", headers["x-powered-by"], "The banner tells an attacker which bugs to try.", ["Remove X-Powered-By."]));
  if (headers["server"] && /\d/.test(headers["server"])) findings.push(finding("server-version", "Server header includes a version", "low", "Disclosure", headers["server"], "A version maps to a public bug list.", ["Strip the version from the Server header."]));
}

function scoreCookies(cookies, findings, passes) {
  if (!cookies.length) {
    passes.push("No cookies were set on the homepage.");
    return;
  }
  const missingSecure = [];
  const missingHttpOnly = [];
  for (const raw of cookies) {
    const name = raw.split("=")[0].trim();
    const attrs = raw.split(";").slice(1).map((part) => part.trim().toLowerCase());
    const has = (key) => attrs.some((attr) => attr === key || attr.startsWith(`${key}=`));
    if (!has("secure")) missingSecure.push(name);
    if (!has("httponly")) missingHttpOnly.push(name);
  }
  if (missingSecure.length) findings.push(finding("cookie-secure", "Cookies are missing the Secure flag", "mild", "Cookies", missingSecure.join(", "), "Those cookies can ride a cleartext request.", ["Add Secure to every cookie on this host."]));
  if (missingHttpOnly.length) findings.push(finding("cookie-httponly", "Cookies can be read by script", "mild", "Cookies", missingHttpOnly.join(", "), "Injected script can copy a cookie that is not HttpOnly.", ["Add HttpOnly to session cookies."]));
}

function scoreHttp(httpResult, findings, passes, reach) {
  if (!httpResult.ok) {
    if (/refuse/i.test(httpResult.error)) {
      passes.push("Port 80 is closed.");
      reach.push({ step: "HTTP 80", result: "Closed" });
    } else reach.push({ step: "HTTP 80", result: httpResult.error });
    return;
  }
  const location = httpResult.value.location || "";
  const redirect = [301, 302, 303, 307, 308].includes(httpResult.value.status);
  reach.push({ step: "HTTP 80", result: redirect ? `${httpResult.value.status} → ${location || "no location"}` : `Status ${httpResult.value.status}` });
  if (redirect && /^https:\/\//i.test(location)) passes.push("Port 80 redirects to HTTPS.");
  else findings.push(finding("http-open", "Port 80 does not send users to HTTPS", "extreme", "Transport", `Status ${httpResult.value.status}.`, "A cleartext listener can be changed on the path.", ["Answer port 80 with a 301 to the https:// version."]));
}

function scoreMail(mail, findings, passes, reach) {
  reach.push({ step: "MX", result: mail.mx === "present" ? "Mail exchange is published" : mail.mx === "absent" ? "No mail exchange" : "Could not be read" });
  reach.push({ step: "SPF", result: mail.spf.length ? mail.spf.join(" | ") : "None" });
  reach.push({ step: "DMARC", result: mail.dmarc || "None" });
  reach.push({ step: "CAA", result: mail.caa.length ? mail.caa.join(" | ") : "None" });
  if (mail.mx === "absent" && mail.spf.length === 0) {
    passes.push("No mail exchange was published, so mailbox spoofing was not scored.");
    return;
  }
  if (mail.spf.length === 0) findings.push(finding("spf-missing", "No SPF record", "mild", "Mail", "No v=spf1 TXT record.", "Any server can claim to send mail for this domain.", ["Publish one SPF TXT record ending in -all or, while testing, ~all."]));
  else if (/(?:^|\s)\+?all\b/i.test(mail.spf[0]) && !/(?:^|\s)[~?-]all\b/i.test(mail.spf[0])) {
    findings.push(finding("spf-plus", "SPF allows the entire internet to send as you", "extreme", "Mail", mail.spf[0], "+all means a forged message still passes SPF.", ["Replace +all with -all after every real sender is listed."]));
  } else if (/(?:^|\s)[~?]all\b/i.test(mail.spf[0])) findings.push(finding("spf-soft", "SPF does not hard-fail forgeries", "mild", "Mail", mail.spf[0], "Soft fail still lets many forgeries through.", ["Move to -all once every real sender is listed."]));
  else if (/(?:^|\s)-all\b/i.test(mail.spf[0])) passes.push("SPF ends in -all.");
  if (!mail.dmarc) findings.push(finding("dmarc-missing", "No DMARC policy", "mild", "Mail", "No _dmarc TXT record.", "SPF alone does not cover the visible From address.", ["Publish v=DMARC1; p=quarantine; rua=mailto:you@yourdomain."]));
  else if (/p=none/i.test(mail.dmarc)) findings.push(finding("dmarc-none", "DMARC is monitor-only", "low", "Mail", mail.dmarc, "p=none does not ask receivers to quarantine forgeries.", ["Change p=none to p=quarantine, then p=reject."]));
  else if (/p=(quarantine|reject)/i.test(mail.dmarc)) passes.push("DMARC is enforcing.");
  if (mail.caa.length === 0) findings.push(finding("caa-missing", "No CAA record", "low", "DNS", "No CAA records.", "Any public CA may issue a certificate for this name.", ["Publish a CAA record for the authority you use."]));
  else passes.push("CAA records limit which authorities can issue certificates.");
}

async function readMail(apex) {
  const miss = (error, empty) => {
    const code = error && error.code;
    if (code === "ENODATA" || code === "ENOTFOUND" || code === "ENOTIMP") return empty;
    return null;
  };
  const [mx, txt, dmarcTxt, caa] = await Promise.all([
    dns.resolveMx(apex).then((rows) => (rows.length ? "present" : "absent"), (error) => miss(error, "absent")),
    dns.resolveTxt(apex).then((rows) => rows.map((chunks) => chunks.join("")), (error) => miss(error, [])),
    dns.resolveTxt(`_dmarc.${apex}`).then((rows) => rows.map((chunks) => chunks.join("")), (error) => miss(error, [])),
    dns.resolveCaa(apex).then((rows) => rows.map((row) => `${row.critical} ${row.issue || row.issuewild || ""}`.trim()), (error) => miss(error, [])),
  ]);
  return {
    mx: mx || "unknown",
    spf: txt ? txt.filter((record) => record.toLowerCase().startsWith("v=spf1")) : [],
    dmarc: dmarcTxt ? dmarcTxt.find((record) => record.toLowerCase().includes("v=dmarc1")) || null : null,
    caa: caa || [],
  };
}

function readHttps(ip, host) {
  return follow(ip, host);
}

async function follow(ip, host) {
  let path = "/";
  let last = null;
  for (let hop = 0; hop < 3; hop += 1) {
    const snap = await requestOnce("https", ip, host, path);
    last = snap;
    if (![301, 302, 303, 307, 308].includes(snap.status) || !snap.location) break;
    if (snap.location.startsWith("/") && !snap.location.startsWith("//")) path = snap.location;
    else {
      try {
        const url = new URL(snap.location);
        if (url.protocol !== "https:" || url.hostname.toLowerCase() !== host) break;
        path = url.pathname || "/";
      } catch {
        break;
      }
    }
  }
  return last;
}

function requestOnce(protocol, ip, host, path) {
  return new Promise((resolve, reject) => {
    const lib = protocol === "https" ? https : http;
    const req = lib.request({
      host: ip,
      port: protocol === "https" ? 443 : 80,
      method: "GET",
      path,
      family: net.isIP(ip) === 6 ? 6 : 4,
      servername: protocol === "https" ? host : undefined,
      rejectUnauthorized: false,
      headers: { Host: host, "User-Agent": UA, Accept: "*/*", Connection: "close" },
      timeout: 6000,
    }, (response) => {
      const headers = {};
      for (const [key, value] of Object.entries(response.headers)) {
        if (value == null || key.toLowerCase() === "set-cookie") continue;
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
      }
      const rawCookies = response.headers["set-cookie"] || [];
      const location = Array.isArray(response.headers.location) ? response.headers.location[0] : response.headers.location || null;
      response.resume();
      response.on("end", () => resolve({
        status: response.statusCode || 0,
        headers,
        cookies: Array.isArray(rawCookies) ? rawCookies : [rawCookies],
        location,
      }));
    });
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    req.end();
  });
}

function errorText(error) {
  const code = error && error.code;
  if (code === "ECONNREFUSED" || /refuse/i.test(error?.message || "")) return "Connection refused";
  if (/timed out|timeout/i.test(error?.message || "")) return "Timed out";
  return "The host did not answer.";
}
