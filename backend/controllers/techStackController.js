/**
 * Technology Stack & Hosting Detector Controller
 */

const { detectTechStack } = require('../seo/techStack');

async function handleTechStack(req, res, parsedUrl) {
  res.setHeader('Content-Type', 'application/json');
  let target = parsedUrl?.searchParams?.get('url');

  if (!target && (req.method === 'POST' || req.method === 'PUT')) {
    try {
      const body = await new Promise((resolve) => {
        let b = '';
        req.on('data', (c) => (b += c));
        req.on('end', () => resolve(b));
      });
      if (body) {
        const parsed = JSON.parse(body);
        target = parsed.url || parsed.target;
      }
    } catch {}
  }

  if (!target) {
    res.writeHead(400);
    return res.end(JSON.stringify({ success: false, error: true, message: 'Missing "url" parameter.' }));
  }

  try {
    const report = await detectTechStack(target);
    res.writeHead(200);
    res.end(JSON.stringify({ success: true, data: report, ...report }));
  } catch (err) {
    res.writeHead(200);
    res.end(
      JSON.stringify({
        success: false,
        error: true,
        message: `Tech stack detection failed: ${err.message}`,
      })
    );
  }
}

module.exports = {
  handleTechStack,
};
