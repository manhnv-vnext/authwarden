import { readText, getLines, isTestPath } from '../utils/fileContext.js';

/**
 * AI Agent & MCP (Model Context Protocol) Security Scanner
 * Audits AI tool configs, MCP server manifests, and prompt injection boundaries.
 */

// Phrases that have no place in a tool description: they address the model, not the user.
const TOOL_POISONING = new RegExp([
  '<\\s*(?:IMPORTANT|SYSTEM|SECRET|HIDDEN|INSTRUCTIONS?)\\s*>',
  'ignore (?:all |any )?(?:previous|prior|above|other) instructions',
  'do not (?:tell|mention|inform|reveal|show)[^.\\n]{0,40}\\b(?:user|human)',
  '(?:before|prior to) (?:using|calling|invoking) (?:this|any|the) tool[^.\\n]{0,120}\\b(?:read|send|include|pass|upload)\\b',
  '\\b(?:read|send|pass|include|upload)\\b[^.\\n]{0,60}(?:~/\\.ssh|id_rsa|\\.aws/credentials|\\.env\\b)'
].join('|'), 'i');

const MCP_TOOL_SOURCE = /@mcp\.tool|FastMCP\s*\(|\bserver\.(?:tool|registerTool)\s*\(|new\s+McpServer\s*\(|"inputSchema"\s*:/;

/** Line number and snippet of the first line matching regex (falls back to line 1). */
function locate(lines, regex, fallbackSnippet, redactValue = false) {
  const idx = firstLine(lines, regex);
  if (idx === null) return { line: 1, snippet: fallbackSnippet };
  let snippet = lines[idx].trim();
  if (redactValue) snippet = snippet.replace(/(:\s*")[^"]*(")/, '$1***$2');
  return { line: idx + 1, snippet };
}

function firstLine(lines, regex) {
  const idx = lines.findIndex(l => regex.test(l));
  return idx === -1 ? null : idx;
}

export function scanMcpAgent(file) {
  const findings = [];
  const fileName = file.name.toLowerCase();
  const relPath = file.relative.replace(/\\/g, '/');

  // Detect MCP or Agent Configs
  const isAgentConfig = fileName.includes('mcp') || 
                        fileName.includes('claude_desktop_config') || 
                        fileName.includes('agent') || 
                        relPath.includes('.cursor') || 
                        relPath.includes('skills/');

  const content = readText(file);
  if (content === null) return findings;
  const lines = getLines(file);

  // 0. Tool poisoning: hidden instructions inside MCP tool descriptions (MCP-005)
  if ((isAgentConfig || MCP_TOOL_SOURCE.test(content)) && !isTestPath(relPath)) {
    lines.forEach((line, idx) => {
      if (TOOL_POISONING.test(line)) {
        findings.push({
          ruleId: 'MCP-005',
          severity: 'HIGH',
          title: 'Hidden Instruction in MCP Tool Description (Tool Poisoning)',
          file: relPath,
          line: idx + 1,
          snippet: line.trim().slice(0, 200),
          description: 'A tool description or prompt contains text addressed to the model (hidden tags, requests to keep something from the user or to read local secrets). MCP clients pass descriptions to the model verbatim, so this can hijack the agent.',
          remediation: 'Remove model-directed instructions from tool descriptions. Review the server before connecting it and pin its version.'
        });
      }
    });
  }

  if (!isAgentConfig) return findings;

  // 1. Unrestricted Shell Execution in MCP Servers
  if (/mcpServers/i.test(content) || /"command"\s*:/i.test(content)) {
    if (/\b(bash|sh|zsh|cmd\.exe|powershell)\b/i.test(content) && !/sandbox|docker/i.test(content)) {
      findings.push({
        ruleId: 'MCP-001',
        severity: 'CRITICAL',
        title: 'Unsandboxed Shell Execution Tool in MCP Server Config',
        file: relPath,
        ...locate(lines, /"command"\s*:\s*"[^"]*\b(?:bash|sh|zsh|cmd\.exe|powershell)\b|\b(?:bash|sh|zsh|cmd\.exe|powershell)\b/i, 'mcpServers: { ... command: "bash" | "powershell" ... }'),
        description: 'An MCP server is configured to spawn an interactive shell without containerization or sandbox boundaries. Prompt injection can lead to direct host compromise.',
        remediation: 'Run MCP tool execution inside a sandboxed container (Docker/gVisor) and restrict permitted subcommands.'
      });
    }

    // 2. Root Filesystem Allowed Paths
    if (/"(args|env|path|allowedDirectories)"\s*:\s*\[?[^\]]*["'](\/|~|\/etc|\/root|C:\\)["']/i.test(content)) {
      findings.push({
        ruleId: 'MCP-002',
        severity: 'HIGH',
        title: 'Unrestricted Filesystem Path Given to MCP Server',
        file: relPath,
        ...locate(lines, /["'](?:\/|~|\/etc|\/root|C:\\)["']/i, 'allowedDirectories: ["/"]'),
        description: 'AI Agent is granted read/write access to the entire root filesystem or home directory. Any prompt injection can read SSH keys or system secrets.',
        remediation: 'Scope allowed directories strictly to the specific project directory.'
      });
    }

    // 3. Hardcoded Secret in MCP Server Config (MCP-003)
    if (/"env"\s*:\s*\{[^}]*"(?:[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|AUTH)[A-Z0-9_]*)"\s*:\s*"([^"]{12,})"/i.test(content)) {
      findings.push({
        ruleId: 'MCP-003',
        severity: 'CRITICAL',
        title: 'Hardcoded Secret / API Token in MCP Configuration',
        file: relPath,
        ...locate(lines, /"[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|AUTH)[A-Z0-9_]*"\s*:\s*"[^"]{12,}"/i, 'env: { ... SECRET_KEY: "***" ... }', true),
        description: 'MCP server configuration bakes sensitive API keys or credentials directly into config files, risking credential exposure via git or tool sharing.',
        remediation: 'Pass sensitive API tokens via runtime process environment variables rather than hardcoding them in MCP JSON manifests.'
      });
    }
  }

  // 3. Prompt Injection Risk in Prompts / System instructions
  if (file.ext === '.md' || file.ext === '.txt' || file.ext === '.json') {
    if (/system_prompt|systemPrompt|instructions/i.test(content)) {
      if (content.includes('{user_input}') || content.includes('${input}') || content.includes('{{query}}')) {
        if (!content.includes('```') && !content.includes('<user_input>') && !content.includes('<user_query>')) {
          findings.push({
            ruleId: 'MCP-004',
            severity: 'MEDIUM',
            title: 'Unescaped User Input Concatenation in AI System Prompt',
            file: relPath,
            line: 1,
            snippet: '... {user_input} ...',
            description: 'User input is interpolated into system instructions without XML encapsulation tags (e.g. <user_query>). Attackers can hijack agent control.',
            remediation: 'Wrap untrusted user inputs with explicit delimiters: "<user_query>\\n${userInput}\\n</user_query>" and instruct the LLM never to follow commands inside that tag.'
          });
        }
      }
    }
  }

  return findings;
}
