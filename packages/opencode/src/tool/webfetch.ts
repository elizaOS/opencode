import dns from "node:dns/promises"
import { Effect, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/unstable/http"
import { Parser } from "htmlparser2"
import * as Tool from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { isImageAttachment } from "@/util/media"

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes

// SSRF guard: refuse fetches to loopback / private / link-local / metadata
// hosts. webfetch can be driven by autonomous (and potentially prompt-injected)
// agents, so a bare GET must not be usable to reach internal services (a local
// dev/control server, cloud metadata at 169.254.169.254, private LAN hosts).
//
// Escape hatch (mainly for tests that legitimately fetch a loopback server):
// set OPENCODE_WEBFETCH_ALLOW_PRIVATE_HOSTS=1 to disable both the hostname
// classifier and the DNS-resolution check below.
export function isPrivateHostsAllowed(): boolean {
  const v = process.env["OPENCODE_WEBFETCH_ALLOW_PRIVATE_HOSTS"]
  return v === "1" || v === "true"
}

// Classify a dotted-quad IPv4 address. Returns true for loopback / private /
// link-local / this-host ranges that must not be reachable via webfetch.
function isBlockedIPv4(a: number, b: number): boolean {
  if (a === 127 || a === 10 || a === 0) return true // loopback / private / this-host
  if (a === 169 && b === 254) return true // link-local + cloud metadata (169.254.169.254)
  if (a === 192 && b === 168) return true // private
  if (a === 172 && b >= 16 && b <= 31) return true // private
  return false
}

// Parse an IPv4-mapped IPv6 tail (either dotted "::ffff:127.0.0.1" or hex
// "::ffff:7f00:1") into its two leading octets, or undefined if not mapped.
function mappedIPv4Octets(host: string): [number, number] | undefined {
  const dotted = host.match(/^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (dotted) return [Number(dotted[1]), Number(dotted[2])]
  const hex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (hex) {
    const hi = parseInt(hex[1], 16)
    const lo = parseInt(hex[2], 16)
    return [(hi >> 8) & 0xff, hi & 0xff] // a.b from the high 16 bits (c.d comes from lo)
  }
  return undefined
}

export function isBlockedFetchHost(rawHost: string): boolean {
  let host = rawHost
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .trim()
  // Strip a single trailing dot (FQDN root, e.g. "localhost.") so suffix and
  // exact comparisons still match.
  if (host.endsWith(".")) host = host.slice(0, -1)
  if (!host) return true
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "::"
  )
    return true
  // IPv6 literals (contain a colon).
  if (host.includes(":")) {
    // IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:hhhh:hhhh) tunnels an IPv4
    // target through an IPv6 literal; classify the embedded IPv4.
    const mapped = mappedIPv4Octets(host)
    if (mapped && isBlockedIPv4(mapped[0], mapped[1])) return true
    // unique-local fc00::/7 (fc.. / fd..) + link-local fe80::/10 (fe8. / fe9. / fea. / feb.)
    if (host.startsWith("fc") || host.startsWith("fd") || /^fe[89ab]/.test(host)) return true
    return false
  }
  // IPv4 dotted-quad ranges
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (m && isBlockedIPv4(Number(m[1]), Number(m[2]))) return true
  return false
}

export const Parameters = Schema.Struct({
  url: Schema.String.annotate({ description: "The URL to fetch content from" }),
  format: Schema.Literals(["text", "markdown", "html"])
    .annotate({
      description: "The format to return the content in (text, markdown, or html). Defaults to markdown.",
      default: "markdown",
    })
    .pipe(Schema.optional, Schema.withDecodingDefault(Effect.succeed("markdown" as const))),
  timeout: Schema.optional(Schema.Number).annotate({ description: "Optional timeout in seconds (max 120)" }),
})

export const WebFetchTool = Tool.define(
  "webfetch",
  Effect.gen(function* () {
    const http = yield* HttpClient.HttpClient
    const httpOk = HttpClient.filterStatusOk(http)

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context) =>
        Effect.gen(function* () {
          if (!params.url.startsWith("http://") && !params.url.startsWith("https://")) {
            throw new Error("URL must start with http:// or https://")
          }

          {
            let host = ""
            try {
              host = new URL(params.url).hostname
            } catch {
              throw new Error(`Invalid URL: ${params.url}`)
            }
            if (!isPrivateHostsAllowed()) {
              if (isBlockedFetchHost(host)) {
                throw new Error(`Refusing to fetch internal/private/loopback host: ${host}`)
              }
              // DNS-resolution check: a public hostname can still resolve to an
              // internal address (DNS rebinding, *.nip.io, split-horizon DNS).
              // Reject if any resolved address is in a blocked range. A literal
              // IP resolves to itself, so this also backstops the string check.
              const bracketless = host.replace(/^\[|\]$/g, "")
              const resolved = yield* Effect.tryPromise(() => dns.lookup(bracketless, { all: true })).pipe(
                Effect.orElseSucceed(() => [] as { address: string; family: number }[]),
              )
              for (const { address } of resolved) {
                if (isBlockedFetchHost(address)) {
                  throw new Error(`Refusing to fetch ${host}: resolves to internal/private/loopback address ${address}`)
                }
              }
              // Residual gap: FetchHttpClient follows HTTP redirects automatically
              // (redirect: "follow") and re-validation of each redirect hop is not
              // implemented here, because the httpOk/filterStatusOk pipeline below
              // would require manual redirect handling to intercept. A public URL
              // that 3xx-redirects to a private address is therefore NOT blocked.
              // Tracked as a known limitation of this guard.
            }
          }

          yield* ctx.ask({
            permission: "webfetch",
            patterns: [params.url],
            always: ["*"],
            metadata: {
              url: params.url,
              format: params.format,
              timeout: params.timeout,
            },
          })

          const timeout = Math.min((params.timeout ?? DEFAULT_TIMEOUT / 1000) * 1000, MAX_TIMEOUT)

          // Build Accept header based on requested format with q parameters for fallbacks
          let acceptHeader = "*/*"
          switch (params.format) {
            case "markdown":
              acceptHeader = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
              break
            case "text":
              acceptHeader = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
              break
            case "html":
              acceptHeader =
                "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
              break
            default:
              acceptHeader =
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
          }
          const headers = {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            Accept: acceptHeader,
            "Accept-Language": "en-US,en;q=0.9",
          }

          const request = HttpClientRequest.get(params.url).pipe(HttpClientRequest.setHeaders(headers))

          // Retry with honest UA if blocked by Cloudflare bot detection (TLS fingerprint mismatch)
          const response = yield* httpOk.execute(request).pipe(
            Effect.catchIf(
              (err) =>
                err.reason._tag === "StatusCodeError" &&
                err.reason.response.status === 403 &&
                err.reason.response.headers["cf-mitigated"] === "challenge",
              () =>
                httpOk.execute(
                  HttpClientRequest.get(params.url).pipe(
                    HttpClientRequest.setHeaders({ ...headers, "User-Agent": "opencode" }),
                  ),
                ),
            ),
            Effect.timeoutOrElse({ duration: timeout, orElse: () => Effect.die(new Error("Request timed out")) }),
          )

          // Check content length
          const contentLength = response.headers["content-length"]
          if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
            throw new Error("Response too large (exceeds 5MB limit)")
          }

          const arrayBuffer = yield* response.arrayBuffer
          if (arrayBuffer.byteLength > MAX_RESPONSE_SIZE) {
            throw new Error("Response too large (exceeds 5MB limit)")
          }

          const contentType = response.headers["content-type"] || ""
          const mime = contentType.split(";")[0]?.trim().toLowerCase() || ""
          const title = `${params.url} (${contentType})`

          if (isImageAttachment(mime)) {
            const base64Content = Buffer.from(arrayBuffer).toString("base64")
            return {
              title,
              output: "Image fetched successfully",
              metadata: {},
              attachments: [
                {
                  type: "file" as const,
                  mime,
                  url: `data:${mime};base64,${base64Content}`,
                },
              ],
            }
          }

          const content = new TextDecoder().decode(arrayBuffer)

          // Handle content based on requested format and actual content type
          switch (params.format) {
            case "markdown":
              if (contentType.includes("text/html")) {
                const markdown = convertHTMLToMarkdown(content)
                return {
                  output: markdown,
                  title,
                  metadata: {},
                }
              }
              return { output: content, title, metadata: {} }

            case "text":
              if (contentType.includes("text/html")) {
                return { output: extractTextFromHTML(content), title, metadata: {} }
              }
              return { output: content, title, metadata: {} }

            case "html":
              return { output: content, title, metadata: {} }

            default:
              return { output: content, title, metadata: {} }
          }
        }).pipe(Effect.orDie),
    }
  }),
)

function extractTextFromHTML(html: string) {
  let text = ""
  let skipDepth = 0

  const parser = new Parser({
    onopentag(name) {
      if (skipDepth > 0 || ["script", "style", "noscript", "iframe", "object", "embed"].includes(name)) {
        skipDepth++
      }
    },
    ontext(input) {
      if (skipDepth === 0) text += input
    },
    onclosetag() {
      if (skipDepth > 0) skipDepth--
    },
  })

  parser.write(html)
  parser.end()

  return text.trim()
}

function convertHTMLToMarkdown(html: string): string {
  const turndownService = new TurndownService({
    headingStyle: "atx",
    hr: "---",
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "*",
  })
  turndownService.remove(["script", "style", "meta", "link"])
  return turndownService.turndown(html)
}
