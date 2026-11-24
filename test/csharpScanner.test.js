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

test('detects NuGet vulnerabilities in .csproj with reachability analysis in C#', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-nuget-csproj-'));
  const csprojFile = path.join(tmpDir, 'CloudPrint.csproj');
  const csFile = path.join(tmpDir, 'PrintJobService.cs');

  const csprojXml = `
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.2" />
    <PackageReference Include="Microsoft.Data.SqlClient" Version="5.0.0" />
  </ItemGroup>
</Project>
`;
  const csCode = `
using Newtonsoft.Json;

namespace CloudPrint;

public class PrintJobService
{
    public void Process(string json)
    {
        var obj = JsonConvert.DeserializeObject(json);
    }
}
`;
  fs.writeFileSync(csprojFile, csprojXml);
  fs.writeFileSync(csFile, csCode);

  const res = await runScan(tmpDir);
  const newtonsoftFinding = res.findings.find(f => f.ruleId === 'CVE-2024-21907');
  const sqlClientFinding = res.findings.find(f => f.ruleId === 'CVE-2024-0056');

  assert.ok(newtonsoftFinding, 'Flags CVE-2024-21907 for vulnerable Newtonsoft.Json');
  assert.equal(newtonsoftFinding.isReachable, true, 'Newtonsoft.Json should be reachable due to using Newtonsoft.Json');
  assert.ok(sqlClientFinding, 'Flags CVE-2024-0056 for vulnerable Microsoft.Data.SqlClient');
  assert.equal(sqlClientFinding.isReachable, false, 'Microsoft.Data.SqlClient not imported in code');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects NuGet lockfile vulnerabilities in packages.lock.json', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-nuget-lock-'));
  const lockFile = path.join(tmpDir, 'packages.lock.json');
  const lockJson = {
    version: 1,
    dependencies: {
      "net9.0": {
        "RestSharp": {
          "type": "Direct",
          "requested": "[106.11.7, )",
          "resolved": "106.11.7",
          "contentHash": "xyz"
        }
      }
    }
  };
  fs.writeFileSync(lockFile, JSON.stringify(lockJson, null, 2));

  const res = await runScan(tmpDir);
  const restSharpFinding = res.findings.find(f => f.ruleId === 'CVE-2021-27293');
  assert.ok(restSharpFinding, 'Flags CVE-2021-27293 for vulnerable RestSharp in packages.lock.json');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects AUTH-008 and SAST-012 in ASP.NET Core file upload and S3 multipart', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-upload-'));
  const controllerFile = path.join(tmpDir, 'UploadController.cs');
  const csCode = `
using Microsoft.AspNetCore.Mvc;
using Amazon.S3;
using Amazon.S3.Model;

namespace SatoApi.Controllers;

[ApiController]
[Route("api/files")]
public class UploadController : ControllerBase
{
    private readonly IAmazonS3 _s3Client;

    // Unauthenticated file upload (AUTH-008) + Path Traversal (SAST-012)
    [HttpPost("upload-avatar")]
    public async Task<IActionResult> UploadAvatar(IFormFile file)
    {
        var localPath = Path.Combine("/var/uploads", file.FileName);
        using var stream = System.IO.File.Create(localPath);
        await file.CopyToAsync(stream);
        return Ok();
    }

    // S3 Multipart Initiation without [Authorize] (AUTH-008)
    [HttpPost("initiate-multipart")]
    public async Task<IActionResult> InitiateMultipart([FromBody] string fileName)
    {
        var request = new InitiateMultipartUploadRequest
        {
            BucketName = "my-bucket",
            Key = fileName
        };
        var response = await _s3Client.InitiateMultipartUploadAsync(request);
        return Ok(response.UploadId);
    }
}
`;
  fs.writeFileSync(controllerFile, csCode);

  const res = await runScan(tmpDir);
  const auth008 = res.findings.filter(f => f.ruleId === 'AUTH-008');
  const sast012 = res.findings.find(f => f.ruleId === 'SAST-012');

  assert.ok(auth008.length >= 2, 'Should detect unauthenticated file upload endpoints (AUTH-008)');
  assert.ok(sast012, 'Should flag direct use of file.FileName in Path.Combine (SAST-012)');
  assert.ok(res.stats.frameworks.some(f => f.includes('File Upload / Multipart')), 'Should detect File Upload framework');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('does not flag sanitized file upload using Path.GetFileName', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-safe-upload-'));
  const controllerFile = path.join(tmpDir, 'SafeUploadController.cs');
  const csCode = `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace SatoApi.Controllers;

[Authorize]
[ApiController]
[Route("api/safe-files")]
public class SafeUploadController : ControllerBase
{
    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        // Safe: sanitized with Path.GetFileName
        var safeFileName = Path.GetFileName(file.FileName);
        var targetPath = Path.Combine("/var/uploads", safeFileName);
        return Ok();
    }
}
`;
  fs.writeFileSync(controllerFile, csCode);

  const res = await runScan(tmpDir);
  assert.equal(res.findings.some(f => f.ruleId === 'AUTH-008'), false, 'Authorized upload should not trigger AUTH-008');
  assert.equal(res.findings.some(f => f.ruleId === 'SAST-012'), false, 'Path.GetFileName sanitized upload should not trigger SAST-012');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
