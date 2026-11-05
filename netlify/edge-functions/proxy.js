export default async (request, context) => {
  const url = new URL(request.url);
  
  // Extract the target URL from /proxy/https%3A%2F%2F...
  const path = url.pathname.replace("/proxy/", "");
  let targetUrl = decodeURIComponent(path);

  if (!targetUrl.startsWith("http")) {
    targetUrl = "https://" + targetUrl;
  }

  // Security: only allow vercel.app
  const target = new URL(targetUrl);
  if (!target.hostname.endsWith(".vercel.app")) {
    return new Response("Only .vercel.app sites are allowed", { status: 403 });
  }

  try {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "manual",
    });

    // Handle redirects
    if ([301, 302, 307, 308].includes(response.status)) {
      const location = response.headers.get("Location");
      if (location) {
        const newLocation = new URL(location, targetUrl).toString();
        return Response.redirect(`/proxy/${encodeURIComponent(newLocation)}`, response.status);
      }
    }

    const contentType = response.headers.get("Content-Type") || "";
    let body = response.body;

    // Basic HTML link rewriting so navigation stays inside the proxy
    if (contentType.includes("text/html")) {
      let html = await response.text();

      // Rewrite absolute links
      html = html.replace(
        /(href|src|action)=["'](https?:\/\/[^"']+)["']/gi,
        (match, attr, link) => {
          if (link.includes("vercel.app")) {
            return `${attr}="/proxy/${encodeURIComponent(link)}"`;
          }
          return match;
        }
      );

      body = html;
    }

    const newHeaders = new Headers(response.headers);
    newHeaders.delete("content-security-policy");
    newHeaders.delete("x-frame-options");

    return new Response(body, {
      status: response.status,
      headers: newHeaders,
    });
  } catch (err) {
    return new Response(`Error: ${err.message}`, { status: 500 });
  }
};