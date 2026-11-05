const ORIGIN_COOKIE = "proxy_origin";

function getCookie(request, name) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function buildRequestHeaders(request) {
  const headers = new Headers(request.headers);
  // Drop hop-by-hop / platform headers so the origin sees a clean request
  for (const h of ["host", "connection", "cookie", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for", "x-nf-request-id", "x-country", "x-language"]) {
    headers.delete(h);
  }
  return headers;
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
      const newLocation = new URL(location, targetUrl).toString();
      return Response.redirect(`/proxy/${encodeURIComponent(newLocation)}`, response.status);
    }
  }

  const contentType = response.headers.get("Content-Type") || "";
  let body = response.body;

  if (contentType.includes("text/html")) {
    let html = await response.text();

    // Absolute links to vercel.app
    html = html.replace(
      /(href|src|action)=["'](https?:\/\/[^"']+)["']/gi,
      (match, attr, link) =>
        link.includes("vercel.app") ? `${attr}="/proxy/${encodeURIComponent(link)}"` : match
    );

    // Root-relative links (/assets/...) -> proxied origin
    html = html.replace(
      /(href|src|action)=["'](\/(?!\/|proxy\/)[^"']*)["']/gi,
      (match, attr, link) => `${attr}="/proxy/${encodeURIComponent(origin + link)}"`
    );

    body = html;
  }

  const newHeaders = new Headers(response.headers);
  for (const h of ["content-security-policy", "content-security-policy-report-only", "x-frame-options", "content-encoding", "content-length", "transfer-encoding"]) {
    newHeaders.delete(h);
  }
  // Remember origin so un-rewritten paths (JS chunks, fetch calls) can be forwarded
  newHeaders.append("Set-Cookie", `${ORIGIN_COOKIE}=${encodeURIComponent(origin)}; Path=/; SameSite=Lax; Secure`);

  return new Response(body, { status: response.status, headers: newHeaders });
}

export default async (request, context) => {
  const url = new URL(request.url);

  try {
    if (url.pathname.startsWith("/proxy/")) {
      // Also tolerates Netlify decoding %2F and collapsing "//" in the path
      const path = url.pathname.replace(/^\/proxy\/?/, "") + url.search;
      let targetUrl = decodeURIComponent(path);
      if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;
      targetUrl = targetUrl.replace(/^(https?:)\/+/, "$1//");

      const target = new URL(targetUrl);
      if (!target.hostname.endsWith(".vercel.app")) {
        return new Response("Only .vercel.app sites are allowed", { status: 403 });
      }
      return await proxyTo(targetUrl, request);
    }

    // Fallback: forward unknown paths to the last proxied origin
    if (url.pathname !== "/" && url.pathname !== "/index.html") {
      const origin = getCookie(request, ORIGIN_COOKIE);
      if (origin && new URL(origin).hostname.endsWith(".vercel.app")) {
        return await proxyTo(origin + url.pathname + url.search, request);
      }
    }

    return context.next();
  } catch (err) {
    return new Response(`Error: ${err.message}`, { status: 500 });
  }
};
