/* =========================================================
   UTILS.JS — Utilitaires partagés Audit Tools
   ========================================================= */

/**
 * Met à jour le textContent d'un élément par son ID.
 * @param {string} id
 * @param {string|number} val
 */
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/**
 * Formate une taille en octets vers Ko/Mo.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' o';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' Ko';
  return (bytes / 1048576).toFixed(1) + ' Mo';
}

/**
 * Affiche une notification toast temporaire.
 * Requiert un élément #toast dans le DOM.
 * @param {string} msg
 * @param {'ok'|'err'|''} type
 */
function toast(msg, type = '') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.className = 'toast show ' + type;
  setTimeout(() => el.classList.remove('show'), 3000);
}

/**
 * Convertit du Markdown basique en HTML.
 * Supporte : titres, gras, italique, listes, code, blockquotes, HR.
 * @param {string} md
 * @returns {string}
 */
function renderMarkdown(md) {
  return md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    // Blocs de code (avant tout le reste)
    .replace(/```[\s\S]*?```/g, m => {
      const code = m.replace(/^```\w*\n?/, '').replace(/```$/, '');
      return `<pre><code>${code}</code></pre>`;
    })
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Titres
    .replace(/^#### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^### (.+)$/gm,  '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,   '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,    '<h1>$1</h1>')
    // Emphase
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    // Éléments de bloc
    .replace(/^---$/gm, '<hr>')
    .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>')
    .replace(/^\- (.+)$/gm,    '<li>$1</li>')
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    // Paragraphes
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>');
}
