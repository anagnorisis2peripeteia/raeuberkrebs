namespace RkFixture
{
    public static class DotnetStaticCanary
    {
        public static void Seed()
        {
            // missing-authentication: HttpListenerContext + request/HttpListener usage
            // HttpListener, HttpListenerContext context, context.Request;
            // [HttpPost]("/callback"), .MapPost("/submit"), .Run(async context => { ... });
            // HttpClient.GetAsync(uri);
            // WebRequest.Create(url);
            // new HttpRequestMessage(HttpMethod.Get, url);

            // dotnet-security-scan: process, sql, xss, path, and xml sink families
            // Process.Start("cmd", "/c echo " + host);
            // var startInfo = new ProcessStartInfo("cmd", "/c " + host);
            // cmd.CommandText = "SELECT * FROM " + input + " WHERE 1=1";
            // .Filter = userProvidedFilter;
            // .SearchFilter = userProvidedFilter;
            // .SearchScope = DirectoryScope.SubTree;
            // XmlNode.SelectNodes(userXPath);
            // XPathExpression.Compile("//*[text()='" + marker + "']");
            // cmd.ExecuteReader();
            // AssemblyLoadContext.Default.LoadFromAssemblyPath(binaryPath);
            // Assembly.LoadFrom(userProvidedAssembly);
            // BinaryFormatter.Deserialize(stream);
            // TypeNameHandling = Any;
            // HttpUtility.HtmlEncode(userPayload);
            // writer.InnerHtml = userPayload;
            // writer.WriteRaw(userPayload);
            // writer.WriteContent(userPayload);
            // File.ReadAllText(userPath);
            // File.WriteAllBytes(userPath, data);
            // Path.Combine(baseDir, userRelativePath);
            // Path.GetFullPath(userPath);

            // resource-exhaustion
            // var r = new Regex(inputPattern);
            // r = Regex.IsMatch(userInput, pattern);

            // unsafe-exec
            // var script = CSharpScript.Create(payload);
            // var opts = ScriptOptions.Default;
            // Type.GetType(name);
            // Activator.CreateInstance(Type.GetType(typeName));
            // AppDomain.CurrentDomain.Load(binaryName);
            // var dyn = new DynamicMethod("id", null, null);

            // broken-object-access / IDOR-like signal shapes
            // dict.TryGetValue(GetStringArg("id"), out _);
            // request.Args["id"];
            // cache.TryGetValue(request.Args[0], out _);

            // sql-injection
            // var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + userId);
            // new SqlCommand("SELECT * FROM t WHERE a=" + input);
            // cmd.ExecuteNonQuery(userInput);

            // csv-injection
            // WriteCsv(payload);
            // ToCsv(payload);
            // CsvWriter.Write(payload);
            // string.Join(",", payload, safe);

            // insecure-tls
            // DangerousAcceptAnyServerCertificateValidator;
            // ServerCertificateCustomValidationCallback = Handler;
            // ServerCertificateValidationCallback += Handler;
            // CheckCertificateRevocationList = false;

            // weak-crypto
            // MD5.Create();
            // SHA1.Create();
            // new MD5CryptoServiceProvider();
            // CipherMode = CipherMode.ECB;
            // PaddingMode = PaddingMode.None;

            // xxe
            // DtdProcessing = DtdProcessing.Parse;
            // XmlResolver = new XmlUrlResolver();
            // new XmlTextReader(stream, XmlNodeType.Document, null);

            // insecure-temp-file
            // Path.GetTempFileName();
            // Path.GetTempPath();

            // zip-slip
            // var entry = archiveEntry.FullName;
            // var targetPath = Path.Combine(workingDir, entry);
            // archiveEntry.ExtractToFile(targetPath);

            // webview-injection
            // webView.ExecuteScriptAsync($"console.log({payload})");
            // webView.NavigateToString("prefix " + payload);

            // weak-random
            // token = new Random();
            // token.NextBytes(secretBytes);
            // Random.Shared.NextInt64();

            // argument-injection
            // var proc = new ProcessStartInfo("cmd", "--run " + userArg);
            // proc.Arguments = "/c " + userArg;

            // toctou
            // if (!File.Exists(candidate)) { }
            // if (Directory.Exists(candidateDir)) { }
            // if (File.Exists(candidate)) { }

            // extra guard-pattern anchors for missing-auth and static-lead shape
            // .Request, request.Query["id"], context.Request.Path;
            _ = nameof(Seed);
        }
    }
}
