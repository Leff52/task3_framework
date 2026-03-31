import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { applyCors, createRateLimiter, applySecurityHeaders } from "../src/security.js";
import { createItemsRepo } from "../src/items.js";

test("Недоверенный источник не получает разрешающий заголовок", () => {
  const req = { headers: { origin: "http://evil.local" } };
  const headers = new Map();
  const res = { setHeader(k, v) { headers.set(k, v); } };

  applyCors(req, res, ["http://localhost:5173"]);
  assert.equal(headers.has("Access-Control-Allow-Origin"), false);
});

test("Доверенный источник получает разрешающий заголовок", () => {
  const req = { headers: { origin: "http://localhost:5173" } };
  const headers = new Map();
  const res = { setHeader(k, v) { headers.set(k, v); } };

  applyCors(req, res, ["http://localhost:5173"]);
  assert.equal(headers.get("Access-Control-Allow-Origin"), "http://localhost:5173");
});

test("Ограничитель частоты блокирует лишние запросы", () => {
  const limiter = createRateLimiter({ readPerMinute: 2, writePerMinute: 1 });

  const req = { method: "GET", url: "/api/items", socket: { remoteAddress: "1.2.3.4" }, headers: {} };

  assert.equal(limiter.allow(req), true);
  assert.equal(limiter.allow(req), true);
  assert.equal(limiter.allow(req), false);
});

test("Ограничитель отдельно считает read и write", () => {
  const limiter = createRateLimiter({ readPerMinute: 2, writePerMinute: 1 });

  const readReq = { method: "GET", url: "/api/items", socket: { remoteAddress: "1.2.3.4" }, headers: {} };
  const writeReq = { method: "POST", url: "/api/items", socket: { remoteAddress: "1.2.3.4" }, headers: {} };

  // 2 read запроса - ок
  assert.equal(limiter.allow(readReq), true);
  assert.equal(limiter.allow(readReq), true);
  // 3й read - блокирован
  assert.equal(limiter.allow(readReq), false);

  // но write может быть выполнен, так как счётчик отдельный
  assert.equal(limiter.allow(writeReq), true);
  // и второй write - блокирован
  assert.equal(limiter.allow(writeReq), false);
});

test("Защитные заголовки добавляются", () => {
  const headers = new Map();
  const res = { setHeader(k, v) { headers.set(k, v); } };

  applySecurityHeaders(res);

  assert.equal(headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(headers.get("X-Frame-Options"), "DENY");
  assert.equal(headers.get("Cache-Control"), "no-store, max-age=0");
  assert.equal(headers.get("Pragma"), "no-cache");
});

test("Интеграция: GET /api/items с доверенного источника", async () => {
  const repo = createItemsRepo();
  repo.create("Товар1", 100);
  const limiter = createRateLimiter({ readPerMinute: 100, writePerMinute: 100 });

  const server = http.createServer((req, res) => {
    applySecurityHeaders(res);
    applyCors(req, res, ["http://localhost:5173"]);

    if (req.method === "GET" && req.url === "/api/items") {
      if (!limiter.allow(req)) {
        res.statusCode = 429;
        res.end("Слишком много запросов");
        return;
      }
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(repo.list()));
      return;
    }

    res.statusCode = 404;
    res.end("Not found");
  });

  const serverPromise = new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  await serverPromise;
  const port = server.address().port;

  // Запрос с доверенного источника
  const response = await new Promise((resolve) => {
    const options = {
      hostname: "127.0.0.1",
      port: port,
      path: "/api/items",
      method: "GET",
      headers: { "Origin": "http://localhost:5173" }
    };
    const req = http.request(options, resolve);
    req.end();
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["access-control-allow-origin"], "http://localhost:5173");

  server.close();
});

test("Интеграция: GET /api/items с недоверенного источника", async () => {
  const repo = createItemsRepo();
  const limiter = createRateLimiter({ readPerMinute: 100, writePerMinute: 100 });

  const server = http.createServer((req, res) => {
    applySecurityHeaders(res);
    applyCors(req, res, ["http://localhost:5173"]);

    if (req.method === "GET" && req.url === "/api/items") {
      if (!limiter.allow(req)) {
        res.statusCode = 429;
        res.end("Слишком много запросов");
        return;
      }
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(repo.list()));
      return;
    }

    res.statusCode = 404;
    res.end("Not found");
  });

  const serverPromise = new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  await serverPromise;
  const port = server.address().port;

  // Запрос с недоверенного источника
  const response = await new Promise((resolve) => {
    const options = {
      hostname: "127.0.0.1",
      port: port,
      path: "/api/items",
      method: "GET",
      headers: { "Origin": "http://evil.local" }
    };
    const req = http.request(options, resolve);
    req.end();
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["access-control-allow-origin"], undefined);

  server.close();
});
