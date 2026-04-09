"use strict";

const counters = {
  lead_total:   0,
  lead_errors:  0,
  graph_calls:  0,
  graph_errors: 0,
  email_errors: 0
};

function inc(key) { counters[key] = (counters[key] || 0) + 1; }
function get()    { return { uptime: Math.floor(process.uptime()), ...counters }; }

module.exports = { inc, get };
