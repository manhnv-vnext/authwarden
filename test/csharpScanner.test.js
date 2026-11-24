import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runScan } from '../src/index.js';

test('detects ASP.NET Core framework and libraries from .csproj', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-csharp-csproj-'));
  const csprojFile = path.join(tmpDir, 'SatoApi.csproj');
  const csprojXml = `
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="9.0.0" />
    <PackageReference Include="AWSSDK.S3" Version="3.7.400" />
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="9.0.0" />
  </ItemGroup>
</Project>
`;
  fs.writeFileSync(csprojFile, csprojXml);

  const res = await runScan(tmpDir);
  assert.ok(res.stats.frameworks.some(f => f.includes('ASP.NET Core (.NET 9.0)')));
  assert.ok(res.stats.frameworks.some(f => f.includes('JwtBearer (Auth)')));
  assert.ok(res.stats.frameworks.some(f => f.includes('AWS S3 (Storage)')));
  assert.ok(res.stats.frameworks.some(f => f.includes('Entity Framework Core')));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects AUTH-001, AUTH-002, and AUTH-005 in ASP.NET Core Controller', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-csharp-auth-'));
  const controllerFile = path.join(tmpDir, 'AdminController.cs');
  const csCode = `
using Microsoft.AspNetCore.Mvc;

namespace MyApp.Controllers;

[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        return Ok();
    }

    [HttpPost("create")]
    public async Task<IActionResult> CreateItem([FromBody] User user)
    {
        return Ok();
    }
}
`;
  fs.writeFileSync(controllerFile, csCode);

  const res = await runScan(tmpDir);
  const auth001 = res.findings.find(f => f.ruleId === 'AUTH-001');
  const auth002 = res.findings.find(f => f.ruleId === 'AUTH-002');
  const auth005 = res.findings.find(f => f.ruleId === 'AUTH-005');

  assert.ok(auth001, 'Should flag Shadow Admin Route without [Authorize] (AUTH-001)');
  assert.ok(auth002, 'Should flag State-modifying POST without [Authorize] (AUTH-002)');
  assert.ok(auth005, 'Should flag Mass Assignment binding to User entity (AUTH-005)');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects BOLA / IDOR in C# Entity Framework Core query', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-csharp-bola-'));
  const serviceFile = path.join(tmpDir, 'OrderService.cs');
  const csCode = `
public class OrderService
{
    private readonly AppDbContext _context;

    public async Task<Order> GetOrderAsync(int id)
    {
        // Unscoped direct lookup by client ID
        var order = await _context.Orders.FindAsync(id);
        return order;
    }
}
`;
  fs.writeFileSync(serviceFile, csCode);

  const res = await runScan(tmpDir);
  const bola = res.findings.find(f => f.ruleId === 'AUTH-003');
  assert.ok(bola, 'Should detect BOLA / IDOR on unscoped EF Core FindAsync(id)');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects SAST vulnerabilities in C# code: SSRF, SQLi, RCE, Path Traversal, Deserialization, Weak Hash', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-csharp-sast-'));
  const vulnFile = path.join(tmpDir, 'VulnService.cs');
  const csCode = `
using System.Diagnostics;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Microsoft.EntityFrameworkCore;

public class VulnService
{
    public async Task ExecuteOperations(string inputUrl, string rawId, string filePath, string cmd)
    {
        // 1. SSRF (SAST-004)
        var client = new HttpClient();
        var resp = await client.GetAsync(inputUrl);

        // 2. SQLi (SAST-001)
        var sql = await _context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {rawId}").ToListAsync();

        // 3. Command Injection (SAST-002)
        Process.Start("cmd.exe", "/c " + cmd);

        // 4. Path Traversal (SAST-005)
        var content = File.ReadAllText(filePath);

        // 5. Insecure Deserialization (SAST-007)
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };

        // 6. Weak Cryptography (SAST-009)
        var md5 = MD5.Create();
    }
}
`;
  fs.writeFileSync(vulnFile, csCode);

  const res = await runScan(tmpDir);
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-004'), 'Flags SSRF in C# HttpClient');
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-001'), 'Flags SQLi in C# FromSqlRaw');
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-002'), 'Flags Command Injection in C# Process.Start');
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-005'), 'Flags Path Traversal in C# File.ReadAllText');
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-007'), 'Flags Insecure Deserialization in C# TypeNameHandling.All');
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-009'), 'Flags Weak MD5 hash in C# MD5.Create');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects SSL bypass in Dart Flutter code and provides Coverage Scorecard', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-dart-'));
  const dartFile = path.join(tmpDir, 'api_client.dart');
  const dartCode = `
import 'dart:io';

void setupClient(HttpClient client) {
  client.badCertificateCallback = (cert, host, port) => true;
}
`;
  fs.writeFileSync(dartFile, dartCode);

  const res = await runScan(tmpDir);
  assert.ok(res.findings.some(f => f.ruleId === 'SAST-008'), 'Flags badCertificateCallback in Dart');

  // Coverage Transparency scorecard verification
  assert.ok(res.stats.coverageScorecard, 'Coverage scorecard should be attached to stats');
  assert.ok(res.stats.coverageScorecard.some(c => c.target.includes('Flutter / Dart') && c.status === 'ACTIVE'));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects AUTH-001 in Java Spring Boot controller', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-spring-'));
  const javaFile = path.join(tmpDir, 'AdminUserController.java');
  const javaCode = `
package com.example.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/admin/users")
public class AdminUserController {

    @GetMapping("/all")
    public ResponseEntity<String> getAllUsers() {
        return ResponseEntity.ok("users");
    }
}
`;
  fs.writeFileSync(javaFile, javaCode);

  const res = await runScan(tmpDir);
  assert.ok(res.findings.some(f => f.ruleId === 'AUTH-001'), 'Flags Spring Boot admin endpoint missing @PreAuthorize');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
