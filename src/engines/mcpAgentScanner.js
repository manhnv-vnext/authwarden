import fs from 'fs';

/**
 * AI Agent & MCP (Model Context Protocol) Security Scanner
 * Audits AI tool configs, MCP server manifests, and prompt injection boundaries.
 */

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

  if (!isAgentConfig) return findings;

  let content;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    return findings;
  }

  // 1. Unrestricted Shell Execution in MCP Servers
  if (/mcpServers/i.test(content) || /"command"\s*:/i.test(content)) {
    if (/\b(bash|sh|zsh|cmd\.exe|powershell)\b/i.test(content) && !/sandbox|docker/i.test(content)) {
      findings.push({
        ruleId: 'MCP-001',
        severity: 'CRITICAL',
        title: 'Unsandboxed Shell Execution Tool in MCP Server Config',
        file: relPath,
        line: 1,
        snippet: 'mcpServers: { ... command: "bash" | "powershell" ... }',
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
        line: 1,
        snippet: 'allowedDirectories: ["/"]',
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
        line: 1,
        snippet: 'env: { ... SECRET_KEY: "***" ... }',
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
