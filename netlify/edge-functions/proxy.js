const ORIGIN_COOKIE = "proxy_origin";
const HOME_PATH = "/_home";

function getCookie(request, name) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function originCookie(origin) {
  return `${ORIGIN_COOKIE}=${encodeURIComponent(origin)}; Path=/; SameSite=Lax; Secure`;
}

function isAllowed(hostname) {
  return hostname.endsWith(".vercel.app");
}

function isDocumentRequest(request) {
  if (request.method !== "GET") return false;
  const dest = request.headers.get("sec-fetch-dest");
  if (dest) return dest === "document";
  return (request.headers.get("accept") || "").includes("text/html");
}

function redirect(location, status = 302, extraHeaders = {}) {
  return new Response(null, { status, headers: { Location: location, ...extraHeaders } });
}

function buildRequestHeaders(request) {
  const headers = new Headers(request.headers);
  // Drop hop-by-hop / platform headers so the origin sees a clean request
  for (const h of ["host", "connection", "cookie", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for", "x-nf-request-id", "x-country", "x-language"]) {
    headers.delete(h);
  }
  return headers;
}

// Map a URL to where it should be requested from inside the proxy
function toProxyPath(link, origin) {
  const u = new URL(link, origin);
  if (u.origin === origin) return u.pathname + u.search + u.hash;
  if (isAllowed(u.hostname)) return `/proxy/${encodeURIComponent(u.toString())}`;
  return null;
}

async function proxyTo(targetUrl, request) {
  const method = request.method;
  const response = await fetch(targetUrl, {
    method,
    headers: buildRequestHeaders(request),
    body: ["GET", "HEAD"].includes(method) ? undefined : request.body,
    redirect: "manual",
  });

  const origin = new URL(targetUrl).origin;

  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = response.headers.get("Location");
    if (location) {
      const mapped = toProxyPath(location, origin) ?? new URL(location, targetUrl).toString();
      return redirect(mapped, response.status, { "Set-Cookie": originCookie(origin) });
    }
  }

  const contentType = response.headers.get("Content-Type") || "";
  let body = response.body;

  if (contentType.includes("text/html")) {
    let html = await response.text();
    html = html.replace(
      /(href|src|action)=["'](https?:\/\/[^"']+)["']/gi,
      (match, attr, link) => {
        const mapped = toProxyPath(link, origin);
        return mapped ? `${attr}="${mapped}"` : match;
      }
    );
    body = html;
  }

  const newHeaders = new Headers(response.headers);
  for (const h of ["content-security-policy", "content-security-policy-report-only", "x-frame-options", "content-encoding", "content-length", "transfer-encoding"]) {
    newHeaders.delete(h);
  }
  newHeaders.append("Set-Cookie", originCookie(origin));

  return new Response(body, { status: response.status, headers: newHeaders });
}

export default async (request, context) => {
  const url = new URL(request.url);

  try {
    // Landing page: always reachable, clears the active origin
    if (url.pathname === HOME_PATH) {
      const page = await context.rewrite("/index.html");
      const headers = new Headers(page.headers);
      headers.append("Set-Cookie", `${ORIGIN_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax; Secure`);
      return new Response(page.body, { status: page.status, headers });
    }

    if (url.pathname.startsWith("/proxy/")) {
      // Also tolerates Netlify decoding %2F and collapsing "//" in the path
      const path = url.pathname.replace(/^\/proxy\/?/, "") + url.search;
      let targetUrl = decodeURIComponent(path);
      if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;
      targetUrl = targetUrl.replace(/^(https?:)\/+/, "$1//");

      const target = new URL(targetUrl);
      if (!isAllowed(target.hostname)) {
        return new Response("Only .vercel.app sites are allowed", { status: 403 });
      }

      // Page navigations become the active origin and move to the real path so client-side routers work
      if (isDocumentRequest(request)) {
        return redirect(target.pathname + target.search + target.hash, 302, { "Set-Cookie": originCookie(target.origin) });
      }
      return await proxyTo(targetUrl, request);
    }

    const origin = getCookie(request, ORIGIN_COOKIE);
    if (origin && isAllowed(new URL(origin).hostname)) {
      return await proxyTo(origin + url.pathname + url.search, request);
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return context.next();
    }
    return redirect(HOME_PATH);
  } catch (err) {
    return new Response(`Error: ${err.message}`, { status: 500 });
  }
};
