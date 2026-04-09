"use strict";
const fs     = require("fs");
const crypto = require("crypto");
const path   = require("path");

const HTML_FILES = ["index.html", "entra.html", "intune.html", "o365.html", "gpo.html"];
const BASE_DIR   = path.join(__dirname, "..");

function fileHash(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha1").update(content).digest("hex").slice(0, 8);
}

for (const htmlFile of HTML_FILES) {
  const fullHtml = path.join(BASE_DIR, htmlFile);
  if (!fs.existsSync(fullHtml)) continue;

  let html = fs.readFileSync(fullHtml, "utf8");

  html = html.replace(/src="(js\/[^"?]+\.js)"/g, (_, src) => {
    const fullPath = path.join(BASE_DIR, src);
    if (!fs.existsSync(fullPath)) return `src="${src}"`;
    return `src="${src}?v=${fileHash(fullPath)}"`;
  });

  html = html.replace(/href="(css\/[^"?]+\.css)"/g, (_, href) => {
    const fullPath = path.join(BASE_DIR, href);
    if (!fs.existsSync(fullPath)) return `href="${href}"`;
    return `href="${href}?v=${fileHash(fullPath)}"`;
  });

  fs.writeFileSync(fullHtml, html);
  console.log(`Hashes injectés : ${htmlFile}`);
}
