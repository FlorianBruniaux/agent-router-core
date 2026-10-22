These fixtures are constructed from official protocol sources. They are not
captured provider failures and do not establish live authentication, rate limits
or service availability. Classification consumes only the supervised stdout
envelope. Free text, stderr, assistant content, tool output and child-agent
events grant no failure classification. A nonzero process exit is required.

- Claude: official `@anthropic-ai/claude-agent-sdk@0.3.220` published
  [sdk.d.ts](https://unpkg.com/@anthropic-ai/claude-agent-sdk@0.3.220/sdk.d.ts),
  SHA-256 `b415fbff96b9f754bca6e7113c4bf3d278a76e453be1264e9bd1acb9c0b2a836`.
  `SDKAssistantMessage.error` provides `authentication_failed`,
  `oauth_org_not_allowed`, and `rate_limit`; `parent_tool_use_id` distinguishes
  root messages. A matching session's failed terminal `result` is required.
  `SDKResultSuccess.api_error_status` can also carry the native HTTP status;
  only `is_error=true` with 401 or 429 is accepted. Error strings and warnings
  do not classify. No documented network metadata is mapped.
- Codex: official
  [exec_events.rs](https://github.com/openai/codex/blob/main/codex-rs/exec/src/exec_events.rs),
  inspected 2026-09-27. `ThreadErrorEvent` exposes only `message: String`.
  No Authentication, RateLimit or Network class is inferred, even if a future
  or forged event adds status/code fields. The generic crash remains.
- OpenCode, commit `b471c2b4495747353af768fbf2e0790c9d820ce2`:
  [run.ts](https://github.com/anomalyco/opencode/blob/b471c2b4495747353af768fbf2e0790c9d820ce2/packages/opencode/src/cli/cmd/run.ts)
  emits the selected session's `session.error` as a JSON `error` envelope.
  [session.ts](https://github.com/anomalyco/opencode/blob/b471c2b4495747353af768fbf2e0790c9d820ce2/packages/core/src/v1/session.ts)
  defines `ProviderAuthError` and `APIError` with statusCode/isRetryable/metadata.
  [message-v2.ts](https://github.com/anomalyco/opencode/blob/b471c2b4495747353af768fbf2e0790c9d820ce2/packages/opencode/src/session/message-v2.ts),
  SHA-256 `bfeb41e03e3788c83d3a031cce0aa1cf19a82c024a09e2a6aadbebb7a3d40d53`,
  maps the native system code ECONNRESET to `APIError.data.metadata.code`,
  `isRetryable=true`, without an HTTP status. Only this exact network case is
  mapped; arbitrary retryable API errors, HTTP 5xx and decompression failures
  are not assumed to be network failures.
- Copilot: official
  [@github/copilot@1.0.44](https://registry.npmjs.org/@github/copilot/-/copilot-1.0.44.tgz)
  `package/app.js`, SHA-256
  `473255d34d10e49702e781686cd04cfbda89bbe42cfd494c820f7d0e02d6b857`.
  `session.error.data` has `errorType` and optional integer `statusCode`.
  Authentication/authorization requires 401/403, rate_limit requires 429, and
  the terminal CLI result must match the supervisor's nonzero exit code.
  A bare errorType is insufficient: some host paths derive it from text.
  No documented network metadata is mapped.

The evidence carries a static code and the SHA-256 of the complete bounded
stdout. Unknown schemas, contradictory classes, incomplete streams and later
recovery do not manufacture a class. Retry permission remains runtime policy;
these parsers neither retry nor attest the objective.
