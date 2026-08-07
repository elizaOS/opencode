import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { Effect, Layer } from "effect"
import { FetchHttpClient } from "effect/unstable/http"
import { Agent } from "../../src/agent/agent"
import { Truncate } from "@/tool/truncate"
import { WebFetchTool, isBlockedFetchHost } from "../../src/tool/webfetch"
import { SessionID, MessageID } from "../../src/session/schema"
import { Tool } from "@/tool/tool"
import { testEffect } from "../lib/effect"

// The integration tests below spin up a loopback server via Bun.serve and fetch
// its localhost URL, which the SSRF guard would otherwise block. Enable the
// documented escape hatch for the duration of this file's live fetches.
let prevAllowPrivate: string | undefined
beforeAll(() => {
  prevAllowPrivate = process.env["OPENCODE_WEBFETCH_ALLOW_PRIVATE_HOSTS"]
  process.env["OPENCODE_WEBFETCH_ALLOW_PRIVATE_HOSTS"] = "1"
})
afterAll(() => {
  if (prevAllowPrivate === undefined) delete process.env["OPENCODE_WEBFETCH_ALLOW_PRIVATE_HOSTS"]
  else process.env["OPENCODE_WEBFETCH_ALLOW_PRIVATE_HOSTS"] = prevAllowPrivate
})

describe("tool.webfetch isBlockedFetchHost", () => {
  const blocked = [
    "localhost",
    "app.localhost",
    "printer.local",
    "svc.internal",
    "localhost.", // trailing-dot FQDN root
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "169.254.1.1",
    "0.0.0.0",
    "[::1]",
    "::1",
    "[::]",
    "[::ffff:127.0.0.1]", // IPv4-mapped IPv6 loopback (dotted)
    "[::ffff:169.254.169.254]", // IPv4-mapped IPv6 metadata (dotted)
    "::ffff:7f00:1", // IPv4-mapped IPv6 loopback (hex) => 127.0.0.1
    "::ffff:a9fe:a9fe", // IPv4-mapped IPv6 metadata (hex) => 169.254.169.254
    "fe80::1", // link-local
    "fe9f::1", // link-local (fe80::/10, second nibble 9)
    "feb0::1", // link-local (fe80::/10, second nibble b)
    "fc00::1", // unique-local
    "fd12:3456::1", // unique-local
    "", // empty host
  ]
  for (const host of blocked) {
    test(`blocks ${JSON.stringify(host)}`, () => {
      expect(isBlockedFetchHost(host)).toBe(true)
    })
  }

  const allowed = [
    "example.com",
    "api.github.com",
    "8.8.8.8",
    "1.1.1.1",
    "172.32.0.1", // just outside RFC1918 172.16/12
    "172.15.0.1", // just outside RFC1918 172.16/12
    "11.0.0.1", // not 10/8
    "192.169.1.1", // not 192.168/16
    "2606:4700:4700::1111", // public IPv6 (Cloudflare)
    "fec0::1", // fec0::/10 is not fe80::/10 link-local
    "my-fe80-server.com", // hostname that merely starts with fe80
  ]
  for (const host of allowed) {
    test(`allows ${JSON.stringify(host)}`, () => {
      expect(isBlockedFetchHost(host)).toBe(false)
    })
  }
})

const it = testEffect(Layer.mergeAll(FetchHttpClient.layer, Truncate.defaultLayer, Agent.defaultLayer))

const ctx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make("msg_message"),
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

const withFetch = <A, E, R>(
  fetch: (req: Request) => Response | Promise<Response>,
  fn: (url: URL) => Effect.Effect<A, E, R>,
) =>
  Effect.acquireUseRelease(
    Effect.sync(() => Bun.serve({ port: 0, fetch })),
    (server) => fn(server.url),
    (server) => Effect.sync(() => server.stop(true)),
  )

const exec = Effect.fn("WebFetchToolTest.exec")(function* (args: Tool.InferParameters<typeof WebFetchTool>) {
  const info = yield* WebFetchTool
  const tool = yield* info.init()
  return yield* tool.execute(args, ctx)
})

describe("tool.webfetch", () => {
  it.instance("returns image responses as file attachments", () =>
    Effect.gen(function* () {
      const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
      yield* withFetch(
        () => new Response(bytes, { status: 200, headers: { "content-type": "IMAGE/PNG; charset=binary" } }),
        (url) =>
          Effect.gen(function* () {
            const result = yield* exec({ url: new URL("/image.png", url).toString(), format: "markdown" })
            expect(result.output).toBe("Image fetched successfully")
            expect(result.attachments).toBeDefined()
            expect(result.attachments?.length).toBe(1)
            expect(result.attachments?.[0].type).toBe("file")
            expect(result.attachments?.[0].mime).toBe("image/png")
            expect(result.attachments?.[0].url.startsWith("data:image/png;base64,")).toBe(true)
            expect(result.attachments?.[0]).not.toHaveProperty("id")
            expect(result.attachments?.[0]).not.toHaveProperty("sessionID")
            expect(result.attachments?.[0]).not.toHaveProperty("messageID")
          }),
      )
    }),
  )

  it.instance("keeps svg as text output", () =>
    withFetch(
      () =>
        new Response('<svg xmlns="http://www.w3.org/2000/svg"><text>hello</text></svg>', {
          status: 200,
          headers: { "content-type": "image/svg+xml; charset=UTF-8" },
        }),
      (url) =>
        Effect.gen(function* () {
          const result = yield* exec({ url: new URL("/image.svg", url).toString(), format: "html" })
          expect(result.output).toContain("<svg")
          expect(result.attachments).toBeUndefined()
        }),
    ),
  )

  it.instance("keeps text responses as text output", () =>
    withFetch(
      () =>
        new Response("hello from webfetch", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        }),
      (url) =>
        Effect.gen(function* () {
          const result = yield* exec({ url: new URL("/file.txt", url).toString(), format: "text" })
          expect(result.output).toBe("hello from webfetch")
          expect(result.attachments).toBeUndefined()
        }),
    ),
  )

  it.instance("extracts text from html without scripts or styles", () =>
    withFetch(
      () =>
        new Response(
          "<html><head><style>.hidden{}</style><script>alert('x')</script></head><body>Hello <b>world</b></body></html>",
          {
            status: 200,
            headers: { "content-type": "text/html; charset=utf-8" },
          },
        ),
      (url) =>
        Effect.gen(function* () {
          const result = yield* exec({ url: new URL("/page.html", url).toString(), format: "text" })
          expect(result.output).toBe("Hello world")
          expect(result.attachments).toBeUndefined()
        }),
    ),
  )
})
