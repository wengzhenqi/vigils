// Mock stdio MCP server(测试用)——— 暴露 2 个工具:
//   - `echo`:把 input 原样返
//   - `sum`:把 2 个数字加起来
//
// 用于 v0.3 Stage 2 E2E:让 vigil-hub serve 把它 attach 为 upstream,
// mock agent 通过 vigil-hub 调用 → 走过完整 firewall / audit 链。
//
// 协议:JSON-RPC 2.0 NDJSON(每行一个 JSON)。
//
// 不实装 Prompts / Resources / Cancellation —— 只最小 MCP 功能集。

import readline from 'node:readline';

const SERVER_INFO = { name: 'mock-mcp-server', version: '1.0.0' };

const TOOLS = [
  {
    name: 'echo',
    description: 'Echo back the input string',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string' } },
      required: ['text'],
    },
  },
  {
    name: 'sum',
    description: 'Add two numbers',
    inputSchema: {
      type: 'object',
      properties: { a: { type: 'number' }, b: { type: 'number' } },
      required: ['a', 'b'],
    },
  },
];

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

function write(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function errorResp(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

rl.on('line', (line) => {
  const l = line.trim();
  if (!l) return;
  let req;
  try {
    req = JSON.parse(l);
  } catch (e) {
    process.stderr.write(`[mock-upstream] bad json: ${l}\n`);
    return;
  }
  const { id, method, params } = req;

  switch (method) {
    case 'initialize':
      write({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2025-03-26',
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
        },
      });
      break;

    case 'initialized':
    case 'notifications/initialized':
      // notification,不响应
      break;

    case 'ping':
      write({ jsonrpc: '2.0', id, result: {} });
      break;

    case 'tools/list':
      write({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      break;

    case 'tools/call': {
      const name = params?.name;
      const args = params?.arguments ?? {};
      if (name === 'echo') {
        const text = String(args.text ?? '');
        write({
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: `echo: ${text}` }] },
        });
      } else if (name === 'sum') {
        const a = Number(args.a);
        const b = Number(args.b);
        if (!Number.isFinite(a) || !Number.isFinite(b)) {
          write(errorResp(id, -32602, 'invalid params: a and b must be numbers'));
        } else {
          write({
            jsonrpc: '2.0',
            id,
            result: { content: [{ type: 'text', text: String(a + b) }] },
          });
        }
      } else {
        write(errorResp(id, -32601, `unknown tool: ${name}`));
      }
      break;
    }

    case 'shutdown':
      write({ jsonrpc: '2.0', id, result: null });
      process.exit(0);
      break;

    default:
      write(errorResp(id, -32601, `method not implemented: ${method}`));
  }
});

rl.on('close', () => {
  process.stderr.write('[mock-upstream] stdin closed\n');
  process.exit(0);
});

process.stderr.write(`[mock-upstream] ready (pid=${process.pid})\n`);
