package mcpserver

// AcceptHeader is what a client must send on an MCP request.
//
// The streamable HTTP transport lets a server answer either with a single
// JSON body or with an SSE stream, and it chooses per response -- so a client
// has to declare it can read both. The MCP specification requires the header
// for that reason, and the upstream SDK enforces it: a POST whose Accept
// omits either type is answered 400 before any tool runs.
//
// The hand-rolled transport never cared, so every in-house caller was written
// without it and would break on the day the SDK transport becomes the
// default. Setting it is harmless meanwhile -- the built-in transport ignores
// Accept -- which is what makes it safe to fix ahead of the move rather than
// during it.
//
// Exported so the callers that have to send it can name the reason rather
// than repeat the string.
const AcceptHeader = "application/json, text/event-stream"
