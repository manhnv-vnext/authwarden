import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanMcpAgent } from '../src/engines/mcpAgentScanner.js';

test('flags unsandboxed shell execution tool in MCP config (MCP-001)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-mcp-'));
  const mcpFile = path.join(tmpDir, 'mcp_servers.json');

  const config = {
    mcpServers: {
      terminal: {
        command: 'bash',
        args: ['-c']
      }
    }
  };
  fs.writeFileSync(mcpFile, JSON.stringify(config, null, 2));

  const findings = scanMcpAgent({
    path: mcpFile,
    relative: 'mcp_servers.json',
    name: 'mcp_servers.json',
    ext: '.json'
  });

  const mcp1 = findings.find(f => f.ruleId === 'MCP-001');
  assert.ok(mcp1, 'Expected MCP-001 for unsandboxed shell tool');
  assert.equal(mcp1.severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('flags unrestricted root filesystem access in MCP server (MCP-002)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-mcp-'));
  const mcpFile = path.join(tmpDir, 'claude_desktop_config.json');

  const config = {
    mcpServers: {
      filesystem: {
        command: 'node',
        args: ['server.js'],
        allowedDirectories: ['/']
      }
    }
  };
  fs.writeFileSync(mcpFile, JSON.stringify(config, null, 2));

  const findings = scanMcpAgent({
    path: mcpFile,
    relative: 'claude_desktop_config.json',
    name: 'claude_desktop_config.json',
    ext: '.json'
  });

  const mcp2 = findings.find(f => f.ruleId === 'MCP-002');
  assert.ok(mcp2, 'Expected MCP-002 for root directory grant');
  assert.equal(mcp2.severity, 'HIGH');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('flags hardcoded secret in MCP server env config (MCP-003)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-mcp3-'));
  const mcpFile = path.join(tmpDir, 'mcp.json');

  const config = {
    mcpServers: {
      github: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-github'],
        env: {
          GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_secretTokenExample1234567890'
        }
      }
    }
  };
  fs.writeFileSync(mcpFile, JSON.stringify(config, null, 2));

  const findings = scanMcpAgent({
    path: mcpFile,
    relative: 'mcp.json',
    name: 'mcp.json',
    ext: '.json'
  });

  const mcp3 = findings.find(f => f.ruleId === 'MCP-003');
  assert.ok(mcp3, 'Expected MCP-003 for hardcoded token in MCP config');
  assert.equal(mcp3.severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
