# one2x 轨迹记录 Windows 首次安装引导脚本（兼容 Windows PowerShell 5.1 与 PowerShell 7+）
# 仅负责：校验 Ed25519 签名清单、流式下载并核对 SHA-256、在私有暂存目录持有只读锁调用 --first-install。
# 版本判定、防中断录制、回滚与首次同意窗口均由安装包内的 Rust 事务完成。
[CmdletBinding(DefaultParameterSetName = 'Online')]
param(
    [Parameter(ParameterSetName = 'Online')]
    [string]$Repository = 'sunnykui/expert-trajectory-releases',

    [Parameter(ParameterSetName = 'Online')]
    [string]$Proxy = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'Offline')]
    [string]$LocalManifest,

    [Parameter(ParameterSetName = 'SelfTest')]
    [switch]$LoadHelpersOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('One2xTrajBootstrapSecurity' -as [type])) {
    $csharp = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class One2xTrajBootstrapSecurity
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetDiskFreeSpaceExW(
        string lpDirectoryName,
        out ulong lpFreeBytesAvailable,
        out ulong lpTotalNumberOfBytes,
        out ulong lpTotalNumberOfFreeBytes
    );

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileWithSaW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        ref SECURITY_ATTRIBUTES lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string StringSecurityDescriptor,
        uint StringSDRevision,
        out IntPtr SecurityDescriptor,
        IntPtr SecurityDescriptorSize
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor,
        out int lpbDaclPresent,
        out IntPtr pDacl,
        out int lpbDaclDefaulted
    );

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint SetSecurityInfo(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        int ObjectType,
        uint SecurityInfo,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl
    );

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation
    );

    private static IntPtr CreatePrivateSecurityDescriptor(bool inherit)
    {
        string userSid = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
        string flags = inherit ? "OICI" : "";
        string sddl = "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;" + userSid + ")";
        IntPtr sd;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1U, out sd, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return sd;
    }

    public static void ApplyPrivateDacl(Microsoft.Win32.SafeHandles.SafeFileHandle handle, bool inherit)
    {
        const int SE_FILE_OBJECT = 1;
        const uint DACL_SECURITY_INFORMATION = 0x00000004U;
        const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000U;
        IntPtr sd = CreatePrivateSecurityDescriptor(inherit);
        try
        {
            int present, defaulted;
            IntPtr dacl;
            if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out defaulted) || present == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint err = SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                IntPtr.Zero,
                IntPtr.Zero,
                dacl,
                IntPtr.Zero
            );
            if (err != 0)
            {
                throw new Win32Exception((int)err);
            }
        }
        finally
        {
            LocalFree(sd);
        }
    }

    public static FileStream OpenBootstrapLock(string lockPath)
    {
        const uint GENERIC_READ = 0x80000000U;
        const uint GENERIC_WRITE = 0x40000000U;
        const uint WRITE_DAC = 0x00040000U;
        const uint OPEN_ALWAYS = 4U;
        const uint FILE_ATTRIBUTE_NORMAL = 0x00000080U;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000U;
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010U;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400U;
        IntPtr sd = CreatePrivateSecurityDescriptor(false);
        Microsoft.Win32.SafeHandles.SafeFileHandle handle = null;
        try
        {
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.lpSecurityDescriptor = sd;
            sa.bInheritHandle = 0;
            IntPtr raw = CreateFileWithSaW(
                lockPath,
                GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                0U,
                ref sa,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero
            );
            handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(raw, true);
            if (handle.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                handle.Dispose();
                if (err == 32 || err == 33)
                {
                    throw new IOException("另一个 one2x 首次安装引导正在运行，请等待其完成后再试。", new Win32Exception(err));
                }
                throw new Win32Exception(err);
            }
        }
        finally
        {
            LocalFree(sd);
        }
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                throw new InvalidOperationException("首装锁文件不是普通文件（检测到重解析点或目录）");
            }
            ApplyPrivateDacl(handle, false);
            return new FileStream(handle, FileAccess.ReadWrite);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static FileStream CreateNewPrivateFile(string filePath)
    {
        const uint GENERIC_READ = 0x80000000U;
        const uint GENERIC_WRITE = 0x40000000U;
        const uint WRITE_DAC = 0x00040000U;
        const uint CREATE_NEW = 1U;
        const uint FILE_ATTRIBUTE_NORMAL = 0x00000080U;
        IntPtr sd = CreatePrivateSecurityDescriptor(false);
        Microsoft.Win32.SafeHandles.SafeFileHandle handle = null;
        try
        {
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.lpSecurityDescriptor = sd;
            sa.bInheritHandle = 0;
            IntPtr raw = CreateFileWithSaW(
                filePath,
                GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                0U,
                ref sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero
            );
            handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(raw, true);
            if (handle.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(err);
            }
        }
        finally
        {
            LocalFree(sd);
        }
        try
        {
            ApplyPrivateDacl(handle, false);
            return new FileStream(handle, FileAccess.ReadWrite);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static Microsoft.Win32.SafeHandles.SafeFileHandle LockDirectoryNoRename(string directoryPath)
    {
        const uint FILE_LIST_DIRECTORY = 0x0001;
        const uint READ_CONTROL = 0x00020000U;
        const uint WRITE_DAC = 0x00040000U;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        IntPtr raw = CreateFileW(
            directoryPath,
            FILE_LIST_DIRECTORY | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        Microsoft.Win32.SafeHandles.SafeFileHandle handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(raw, true);
        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(err);
        }
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
        {
            int err = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(err);
        }
        if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            handle.Dispose();
            throw new InvalidOperationException("首装暂存目录句柄不是普通目录（检测到重解析点或异常类型）");
        }
        try
        {
            ApplyPrivateDacl(handle, true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
        return handle;
    }

    public static long GetAvailableFreeBytes(string directoryPath)
    {
        ulong avail, total, totalFree;
        if (!GetDiskFreeSpaceExW(directoryPath, out avail, out total, out totalFree))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return avail > (ulong)long.MaxValue ? long.MaxValue : (long)avail;
    }
    private static readonly byte[] Ed25519SpkiPrefix = new byte[] {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    private static readonly BigInteger P = (BigInteger.One << 255) - new BigInteger(19);
    private static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger D;
    private static readonly BigInteger SqrtM1;
    private static readonly ExtPoint BasePoint;

    private struct ExtPoint
    {
        public BigInteger X;
        public BigInteger Y;
        public BigInteger Z;
        public BigInteger T;

        public ExtPoint(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
        {
            X = x; Y = y; Z = z; T = t;
        }
    }

    static One2xTrajBootstrapSecurity()
    {
        BigInteger inv121666 = BigInteger.ModPow(new BigInteger(121666), P - 2, P);
        D = Mod(-new BigInteger(121665) * inv121666);
        SqrtM1 = BigInteger.ModPow(new BigInteger(2), (P - 1) / 4, P);
        BigInteger by = Mod(new BigInteger(4) * BigInteger.ModPow(new BigInteger(5), P - 2, P));
        BigInteger bx;
        if (!RecoverX(by, 0, out bx))
        {
            throw new InvalidOperationException("Ed25519 basepoint initialization failed");
        }
        BasePoint = new ExtPoint(bx, by, BigInteger.One, Mod(bx * by));
    }

    private static BigInteger Mod(BigInteger v)
    {
        BigInteger r = v % P;
        return r.Sign < 0 ? r + P : r;
    }

    private static BigInteger FromLittleEndianUnsigned(byte[] data, int offset, int count)
    {
        byte[] tmp = new byte[count + 1];
        Buffer.BlockCopy(data, offset, tmp, 0, count);
        tmp[count] = 0;
        return new BigInteger(tmp);
    }

    private static bool RecoverX(BigInteger y, int sign, out BigInteger x)
    {
        x = BigInteger.Zero;
        if (y.Sign < 0 || y >= P) return false;
        BigInteger y2 = Mod(y * y);
        BigInteger u = Mod(y2 - BigInteger.One);
        BigInteger v = Mod(D * y2 + BigInteger.One);
        BigInteger v3 = Mod(Mod(v * v) * v);
        BigInteger v7 = Mod(Mod(v3 * v3) * v);
        BigInteger uv3 = Mod(u * v3);
        BigInteger uv7 = Mod(u * v7);
        BigInteger cand = Mod(uv3 * BigInteger.ModPow(uv7, (P - 5) / 8, P));
        BigInteger check = Mod(v * Mod(cand * cand));
        if (check == u)
        {
            x = cand;
        }
        else if (check == Mod(-u))
        {
            x = Mod(cand * SqrtM1);
        }
        else
        {
            return false;
        }
        if (x.IsZero && sign == 1)
        {
            return false;
        }
        if ((int)(x & BigInteger.One) != sign)
        {
            x = P - x;
        }
        return true;
    }

    private static bool DecodePoint(byte[] enc, int offset, out ExtPoint pt)
    {
        pt = new ExtPoint(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        byte[] copy = new byte[32];
        Buffer.BlockCopy(enc, offset, copy, 0, 32);
        int sign = (copy[31] >> 7) & 1;
        copy[31] &= 0x7f;
        BigInteger y = FromLittleEndianUnsigned(copy, 0, 32);
        BigInteger x;
        if (!RecoverX(y, sign, out x))
        {
            return false;
        }
        pt = new ExtPoint(x, y, BigInteger.One, Mod(x * y));
        return true;
    }

    private static ExtPoint PointAdd(ExtPoint p1, ExtPoint p2)
    {
        BigInteger a = Mod((p1.Y - p1.X) * (p2.Y - p2.X));
        BigInteger b = Mod((p1.Y + p1.X) * (p2.Y + p2.X));
        BigInteger c = Mod(Mod(p1.T * new BigInteger(2)) * Mod(D * p2.T));
        BigInteger d = Mod(Mod(p1.Z * new BigInteger(2)) * p2.Z);
        BigInteger e = Mod(b - a);
        BigInteger f = Mod(d - c);
        BigInteger g = Mod(d + c);
        BigInteger h = Mod(b + a);
        return new ExtPoint(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static bool PointEquals(ExtPoint p1, ExtPoint p2)
    {
        return Mod(p1.X * p2.Z - p2.X * p1.Z).IsZero && Mod(p1.Y * p2.Z - p2.Y * p1.Z).IsZero;
    }

    private static bool IsSmallOrder(ExtPoint p)
    {
        ExtPoint q = PointAdd(p, p);
        q = PointAdd(q, q);
        q = PointAdd(q, q);
        ExtPoint id = new ExtPoint(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        return PointEquals(q, id);
    }

    private static ExtPoint ScalarMul(ExtPoint p, BigInteger s)
    {
        ExtPoint acc = new ExtPoint(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        if (s.IsZero) return acc;
        byte[] bytes = s.ToByteArray();
        for (int i = bytes.Length - 1; i >= 0; i--)
        {
            byte b = bytes[i];
            for (int bit = 7; bit >= 0; bit--)
            {
                acc = PointAdd(acc, acc);
                if (((b >> bit) & 1) == 1)
                {
                    acc = PointAdd(acc, p);
                }
            }
        }
        return acc;
    }

    public static byte[] ParseEd25519SpkiPem(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            throw new ArgumentException("发行公钥为空");
        }
        StringBuilder sb = new StringBuilder();
        foreach (string rawLine in pem.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string line = rawLine.Trim();
            if (line.StartsWith("-----", StringComparison.Ordinal)) continue;
            sb.Append(line);
        }
        byte[] der = Convert.FromBase64String(sb.ToString());
        if (der.Length != 44)
        {
            throw new FormatException("Ed25519 SPKI 公钥长度无效");
        }
        for (int i = 0; i < Ed25519SpkiPrefix.Length; i++)
        {
            if (der[i] != Ed25519SpkiPrefix[i])
            {
                throw new FormatException("Ed25519 SPKI 算法头不匹配");
            }
        }
        byte[] key = new byte[32];
        Buffer.BlockCopy(der, 12, key, 0, 32);
        return key;
    }

    public static bool VerifyEd25519Strict(byte[] message, byte[] signature, string spkiPem)
    {
        if (message == null || signature == null || signature.Length != 64)
        {
            return false;
        }
        byte[] pubKey;
        try
        {
            pubKey = ParseEd25519SpkiPem(spkiPem);
        }
        catch
        {
            return false;
        }
        BigInteger s = FromLittleEndianUnsigned(signature, 32, 32);
        if (s.Sign < 0 || s >= L)
        {
            return false;
        }
        ExtPoint aPoint;
        ExtPoint rPoint;
        if (!DecodePoint(pubKey, 0, out aPoint) || !DecodePoint(signature, 0, out rPoint))
        {
            return false;
        }
        if (IsSmallOrder(aPoint) || IsSmallOrder(rPoint))
        {
            return false;
        }
        byte[] hash;
        using (SHA512 sha = SHA512.Create())
        {
            byte[] combined = new byte[64 + message.Length];
            Buffer.BlockCopy(signature, 0, combined, 0, 32);
            Buffer.BlockCopy(pubKey, 0, combined, 32, 32);
            Buffer.BlockCopy(message, 0, combined, 64, message.Length);
            hash = sha.ComputeHash(combined);
        }
        BigInteger k = FromLittleEndianUnsigned(hash, 0, 64) % L;
        ExtPoint lhs = ScalarMul(BasePoint, s);
        ExtPoint rhs = PointAdd(rPoint, ScalarMul(aPoint, k));
        return PointEquals(lhs, rhs);
    }

    public static string ComputeSha256Hex(Stream stream, long expectedLength)
    {
        stream.Position = 0;
        long total = 0;
        byte[] buf = new byte[64 * 1024];
        using (SHA256 sha = SHA256.Create())
        {
            while (true)
            {
                int read = stream.Read(buf, 0, buf.Length);
                if (read <= 0) break;
                total += read;
                if (total > expectedLength)
                {
                    throw new InvalidDataException("安装程序超过清单规定的大小");
                }
                sha.TransformBlock(buf, 0, read, null, 0);
            }
            sha.TransformFinalBlock(buf, 0, 0);
            if (total != expectedLength)
            {
                throw new InvalidDataException("安装程序大小与清单不符");
            }
            StringBuilder hex = new StringBuilder(64);
            foreach (byte b in sha.Hash)
            {
                hex.Append(b.ToString("x2"));
            }
            return hex.ToString();
        }
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -TypeDefinition $csharp -ReferencedAssemblies @('System.Numerics')
    } else {
        Add-Type -TypeDefinition $csharp
    }
}

$script:PinnedReleasePublicKeyPem = @"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAHKXDOnEnePpuVyOzXnIU1sRAAufmcfz0dE+OF9vX6lI=
-----END PUBLIC KEY-----
"@

function Test-One2xRepository([string]$Repo) {
    if ([string]::IsNullOrEmpty($Repo)) { return $false }
    return $Repo -cmatch '^[A-Za-z0-9-]+/(?!\.{1,2}\z)[A-Za-z0-9_.-]+\z'
}

function Test-One2xAllowedUri([Uri]$Uri) {
    if ($null -eq $Uri -or -not $Uri.IsAbsoluteUri) { return $false }
    if ($Uri.Scheme -ne 'https') { return $false }
    if (-not $Uri.IsDefaultPort) { return $false }
    if (-not [string]::IsNullOrEmpty($Uri.UserInfo)) { return $false }
    return $Uri.Host -in @('github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com')
}

function Test-One2xContentRange([string]$Header, [long]$ExpectedStart, [long]$ExpectedTotal) {
    if ([string]::IsNullOrEmpty($Header) -or $ExpectedStart -le 0 -or $ExpectedStart -ge $ExpectedTotal) {
        return $false
    }
    $expectedEnd = $ExpectedTotal - 1
    return $Header.Trim() -ceq "bytes $ExpectedStart-$expectedEnd/$ExpectedTotal"
}

function Test-One2xManifestObject($Manifest, [string]$ExpectedRepository) {
    if ($null -eq $Manifest) { return $false }
    $props = @($Manifest.PSObject.Properties.Name)
    foreach ($req in @('schema_version', 'channel', 'repository', 'version', 'arch', 'exe', 'sha256', 'size', 'notice_version')) {
        if ($props -notcontains $req) { return $false }
    }
    if ([int]$Manifest.schema_version -ne 2) { return $false }
    if ([string]$Manifest.channel -cne 'stable') { return $false }
    if (-not [string]::IsNullOrEmpty($ExpectedRepository) -and ([string]$Manifest.repository -cne $ExpectedRepository)) { return $false }
    if (-not (Test-One2xRepository ([string]$Manifest.repository))) { return $false }
    if ([string]$Manifest.arch -cne 'x86_64') { return $false }
    $ver = [string]$Manifest.version
    $parts = $ver.Split('.')
    if ($parts.Count -ne 3) { return $false }
    foreach ($p in $parts) {
        if ($p -notmatch '^\d+\z') { return $false }
        if ($p.Length -gt 1 -and $p.StartsWith('0')) { return $false }
        [uint64]$parsed = 0
        if (-not [uint64]::TryParse($p, [ref]$parsed)) { return $false }
    }
    if ([string]$Manifest.exe -cne "one2x-traj-setup-$ver.exe") { return $false }
    $size = [long]$Manifest.size
    if ($size -le 0 -or $size -gt (512L * 1024L * 1024L)) { return $false }
    $sha = [string]$Manifest.sha256
    if ($sha.Length -ne 64 -or $sha -notmatch '^[0-9a-fA-F]{64}\z') { return $false }
    if ([string]::IsNullOrEmpty([string]$Manifest.notice_version)) { return $false }
    if ($props -notcontains 'first_install_protocol') { return $false }
    $proto = 0
    if (-not [int]::TryParse([string]$Manifest.first_install_protocol, [ref]$proto) -or $proto -ne 1) { return $false }
    return $true
}

function Enable-One2xTls {
    $proto = [Net.SecurityProtocolType]::Tls12
    $tls13 = [Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13'
    if ($tls13) {
        $proto = $proto -bor ([Net.SecurityProtocolType]'Tls13')
    }
    [Net.ServicePointManager]::SecurityProtocol = $proto
}

function Resolve-One2xWebProxy([string]$ExplicitProxy) {
    $candidate = $ExplicitProxy
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = $env:HTTPS_PROXY
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = $env:https_proxy
    }
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
        $proxyUri = $null
        if (-not [Uri]::TryCreate($candidate.Trim(), [UriKind]::Absolute, [ref]$proxyUri) -or $proxyUri.Scheme -notin @('http', 'https')) {
            throw "代理地址格式无效（请使用如 http://127.0.0.1:7890）：$candidate"
        }
        return (New-Object System.Net.WebProxy($proxyUri))
    }
    try {
        $ie = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($null -ne $ie -and $ie.ProxyEnable -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$ie.ProxyServer)) {
            return [System.Net.WebRequest]::GetSystemWebProxy()
        }
    } catch {}
    return $null
}

$script:ActiveWebProxy = $null

function Open-One2xHttpResponse([Uri]$StartUri, [long]$RangeOffset = 0, [switch]$AllowLoopbackTest) {
    $current = $StartUri
    for ($hop = 0; $hop -le 5; $hop++) {
        $allowed = if ($AllowLoopbackTest) {
            $current.IsLoopback -and $current.Scheme -eq 'http'
        } else {
            Test-One2xAllowedUri $current
        }
        if (-not $allowed) {
            throw "下载地址不符合安全白名单要求：$($current.Host)"
        }
        $req = [System.Net.HttpWebRequest]::CreateHttp($current)
        $req.Method = 'GET'
        $req.AllowAutoRedirect = $false
        $req.Proxy = $script:ActiveWebProxy
        $req.Timeout = 15000
        $req.ReadWriteTimeout = 30000
        $req.UserAgent = 'one2x-traj-windows-bootstrap/1'
        if ($RangeOffset -gt 0) {
            $req.AddRange($RangeOffset)
        }
        try {
            $resp = [System.Net.HttpWebResponse]$req.GetResponse()
        } catch [System.Net.WebException] {
            if ($null -ne $_.Exception.Response) {
                $_.Exception.Response.Dispose()
            }
            throw
        }
        $code = [int]$resp.StatusCode
        if ($code -in @(301, 302, 303, 307, 308)) {
            $loc = $resp.Headers['Location']
            $resp.Dispose()
            if ($hop -ge 5 -or [string]::IsNullOrEmpty($loc)) {
                throw '下载地址跳转次数超限或缺少跳转目标'
            }
            $next = $null
            if (-not [Uri]::TryCreate($current, $loc, [ref]$next)) {
                throw '下载地址跳转目标无效'
            }
            $nextAllowed = if ($AllowLoopbackTest) {
                $next.IsLoopback -and $next.Scheme -eq 'http'
            } else {
                Test-One2xAllowedUri $next
            }
            if (-not $nextAllowed) {
                throw '下载地址跳转目标不在允许的 GitHub 域名内'
            }
            $current = $next
            continue
        }
        return $resp
    }
    throw '下载地址跳转次数超限'
}

function Read-One2xSmallAsset([Uri]$Uri, [int]$MaxBytes) {
    $lastErr = ''
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $resp = $null
        try {
            $resp = Open-One2xHttpResponse -StartUri $Uri -RangeOffset 0
            if ([int]$resp.StatusCode -ne 200) {
                throw "HTTP 状态码 $([int]$resp.StatusCode)"
            }
            if ($resp.ContentLength -gt $MaxBytes) {
                throw '发行清单文件超过大小上限'
            }
            $stream = $resp.GetResponseStream()
            $ms = New-Object System.IO.MemoryStream
            $buf = New-Object byte[] 8192
            while ($true) {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                if (($ms.Length + $n) -gt $MaxBytes) {
                    throw '发行清单文件超过大小上限'
                }
                $ms.Write($buf, 0, $n)
            }
            return ,$ms.ToArray()
        } catch {
            $lastErr = $_.Exception.Message
            if ($attempt -lt 3) {
                Start-Sleep -Seconds (2 * $attempt)
            }
        } finally {
            if ($null -ne $resp) { $resp.Dispose() }
        }
    }
    throw "读取 GitHub 发行文件失败：$lastErr"
}

function Receive-One2xInstaller([Uri]$Uri, [long]$ExpectedSize, [System.IO.FileStream]$FileStream, [switch]$AllowLoopbackTest) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $maxDuration = [TimeSpan]::FromMinutes(20)
    $downloaded = 0L
    $stalledRetries = 0
    $totalAttempts = 0
    $maxStalled = 6
    $maxAttempts = 24
    $progressResetBytes = 256L * 1024L
    $lastError = ''

    while ($stalledRetries -lt $maxStalled -and $totalAttempts -lt $maxAttempts -and $sw.Elapsed -lt $maxDuration) {
        $totalAttempts++
        $attemptStart = $downloaded
        $resp = $null
        try {
            $resp = Open-One2xHttpResponse -StartUri $Uri -RangeOffset $downloaded -AllowLoopbackTest:$AllowLoopbackTest
            $code = [int]$resp.StatusCode
            if ($code -eq 206) {
                $cr = $resp.Headers['Content-Range']
                if (-not (Test-One2xContentRange -Header $cr -ExpectedStart $downloaded -ExpectedTotal $ExpectedSize)) {
                    $stalledRetries++
                    $lastError = '断点续传返回的 Content-Range 不匹配'
                    $FileStream.Position = 0
                    $FileStream.SetLength(0)
                    $downloaded = 0L
                    Start-Sleep -Seconds 2
                    continue
                }
                $FileStream.Position = $downloaded
            } elseif ($code -eq 200) {
                if ($resp.ContentLength -gt $ExpectedSize) {
                    throw '安装程序超过清单规定的大小'
                }
                if ($downloaded -gt 0) {
                    $FileStream.Position = 0
                    $FileStream.SetLength(0)
                    $downloaded = 0L
                }
            } else {
                $stalledRetries++
                $lastError = "HTTP 状态码 $code"
                Start-Sleep -Seconds 2
                continue
            }

            $net = $resp.GetResponseStream()
            $buf = New-Object byte[] (64 * 1024)
            $lastLogAt = $sw.Elapsed
            $lastLoggedBytes = $downloaded
            $streamErr = $null
            while ($sw.Elapsed -lt $maxDuration) {
                try {
                    $n = $net.Read($buf, 0, $buf.Length)
                    if ($n -le 0) { break }
                    $FileStream.Write($buf, 0, $n)
                    $downloaded += $n
                    if ($downloaded -gt $ExpectedSize) {
                        throw '安装程序超过清单规定的大小'
                    }
                    if (($sw.Elapsed - $lastLogAt).TotalSeconds -ge 3 -or ($downloaded - $lastLoggedBytes) -ge (2L * 1024L * 1024L) -or $downloaded -eq $ExpectedSize) {
                        $pct = [int](($downloaded * 100L) / [Math]::Max(1L, $ExpectedSize))
                        Write-Host "正在下载安装包：$downloaded / $ExpectedSize 字节 ($pct%)"
                        $lastLogAt = $sw.Elapsed
                        $lastLoggedBytes = $downloaded
                    }
                } catch {
                    if ($_.Exception.Message -eq '安装程序超过清单规定的大小') { throw }
                    $streamErr = $_.Exception.Message
                    break
                }
            }
            if ($downloaded -eq $ExpectedSize) {
                $FileStream.Flush($true)
                return
            }
            $lastError = if ($null -ne $streamErr) { $streamErr } elseif ($sw.Elapsed -ge $maxDuration) { '下载总耗时超限' } else { '连接提前关闭' }
        } catch {
            if ($_.Exception.Message -eq '安装程序超过清单规定的大小') { throw }
            $lastError = $_.Exception.Message
        } finally {
            if ($null -ne $resp) { $resp.Dispose() }
        }

        $gained = $downloaded - $attemptStart
        if ($gained -ge $progressResetBytes) {
            $stalledRetries = 0
        } else {
            $stalledRetries++
        }
        $FileStream.Flush()
        if ($stalledRetries -lt $maxStalled -and $totalAttempts -lt $maxAttempts -and $sw.Elapsed -lt $maxDuration) {
            Start-Sleep -Seconds 2
        }
    }
    throw "下载安装包未完成（已下载 $downloaded / $ExpectedSize 字节，总尝试 $totalAttempts 次）：$lastError"
}

function Get-One2xFreeSpaceBytes([string]$DirectoryPath) {
    $full = [System.IO.Path]::GetFullPath($DirectoryPath)
    return [One2xTrajBootstrapSecurity]::GetAvailableFreeBytes($full)
}

function Resolve-One2xTrajHome {
    if (-not [string]::IsNullOrEmpty($env:TRAJ_HOME)) {
        return $env:TRAJ_HOME
    }
    $appData = if (-not [string]::IsNullOrEmpty($env:APPDATA)) {
        $env:APPDATA
    } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) 'AppData\Roaming'
    }
    $pointerPath = Join-Path (Join-Path $appData 'one2x-traj') 'location.json'
    if (Test-Path -LiteralPath $pointerPath -PathType Leaf) {
        try {
            $ptr = Get-Content -LiteralPath $pointerPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $ptr -and $null -ne $ptr.PSObject.Properties['home']) {
                $chosen = [string]$ptr.home
                if (-not [string]::IsNullOrEmpty($chosen)) {
                    return $chosen
                }
            }
        } catch {}
    }
    return (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.traj')
}

function Get-One2xDiskReserveBytes {
    $warnMb = 2048L
    $trajHome = Resolve-One2xTrajHome
    $cfgPath = Join-Path $trajHome 'config.json'
    if (Test-Path -LiteralPath $cfgPath -PathType Leaf) {
        try {
            $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $cfg.PSObject.Properties['disk_warn_mb']) {
                $candidate = [long]$cfg.disk_warn_mb
                if ($candidate -gt $warnMb) { $warnMb = $candidate }
            }
        } catch {}
    }
    return ($warnMb * 1024L * 1024L)
}

function Get-One2xSacContext {
    try {
        $val = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop).VerifiedAndReputablePolicyState
        switch ([int]$val) {
            0 { return '关' }
            1 { return '开启（强制拦截无签名程序）' }
            2 { return '评估模式' }
            default { return "未知状态($val)" }
        }
    } catch {
        return '未知'
    }
}

function Format-One2xWin32Block([int]$NativeCode, [string]$ExeName) {
    $sac = Get-One2xSacContext
    if ($NativeCode -in @(225, 226)) {
        return "Windows 安全中心把 one2x 的「$ExeName」当成威胁拦下了（错误 $NativeCode）。请打开「Windows 安全中心 → 病毒和威胁防护 → 保护历史记录」，找到对应记录允许或还原后再试。"
    }
    if ($NativeCode -eq 1260) {
        return "这台电脑的应用控制策略禁止运行「$ExeName」（错误 1260，智能应用控制：$sac）。公司电脑请联系 IT 放行，个人电脑请把本提示发给轨迹采集负责人。"
    }
    if ($NativeCode -ge 4550 -and $NativeCode -le 4599) {
        return "Windows 的「智能应用控制」或系统完整性策略拦截了未签名的「$ExeName」（错误 $NativeCode，智能应用控制：$sac）。不建议自行关闭智能应用控制（关闭后重装系统才能恢复），请把本提示截图发给轨迹采集负责人。"
    }
    return $null
}

function Invoke-One2xTrajBootstrap {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'one2x 轨迹记录 Windows 安装引导仅支持 64 位 Windows 10 / 11。'
    }

    $localAppData = if (-not [string]::IsNullOrEmpty($env:LOCALAPPDATA)) {
        $env:LOCALAPPDATA
    } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) 'AppData\Local'
    }
    $programsDir = Join-Path $localAppData 'Programs'
    if (-not (Test-Path -LiteralPath $programsDir -PathType Container)) {
        New-Item -ItemType Directory -Path $programsDir -Force | Out-Null
    }
    $programsItem = Get-Item -LiteralPath $programsDir -Force
    if (($programsItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "安装父目录包含重解析点，已拒绝继续：$programsDir"
    }

    $bootstrapLockPath = Join-Path $programsDir '.one2x-traj-bootstrap.lock'
    $bootstrapLock = $null
    $stageDir = $null
    $stageDirPin = $null
    $stageCreatedUtc = $null
    $stagedExe = $null
    $stagedExeCreated = $false
    $resultPath = $null
    try {
        $bootstrapLock = [One2xTrajBootstrapSecurity]::OpenBootstrapLock($bootstrapLockPath)

        $manifest = $null
        $offlineExePath = $null
        if (-not [string]::IsNullOrEmpty($LocalManifest)) {
            $manifestFile = [System.IO.Path]::GetFullPath($LocalManifest)
            if (-not (Test-Path -LiteralPath $manifestFile -PathType Leaf)) {
                throw "找不到本地更新清单：$manifestFile"
            }
            $manifestDir = Split-Path -Parent $manifestFile
            $sigFile = [System.IO.Path]::ChangeExtension($manifestFile, '.sig')
            if (-not (Test-Path -LiteralPath $sigFile -PathType Leaf)) {
                throw "找不到本地更新清单签名：$sigFile"
            }
            $manifestInfo = Get-Item -LiteralPath $manifestFile -Force
            if ($manifestInfo.Length -le 0 -or $manifestInfo.Length -gt 16384) {
                throw '本地更新清单大小超出范围'
            }
            $manifestBytes = [System.IO.File]::ReadAllBytes($manifestFile)
            $sigBytes = [System.IO.File]::ReadAllBytes($sigFile)
            if (-not [One2xTrajBootstrapSecurity]::VerifyEd25519Strict($manifestBytes, $sigBytes, $script:PinnedReleasePublicKeyPem)) {
                throw '本地更新清单 Ed25519 签名校验失败'
            }
            $manifest = ([System.Text.Encoding]::UTF8.GetString($manifestBytes)) | ConvertFrom-Json
            if ($null -ne $manifest -and $manifest.PSObject.Properties.Name -notcontains 'first_install_protocol') {
                throw "本地清单对应的版本 $($manifest.version) 尚未包含安全首装协议（first_install_protocol），请直接双击安装包手动安装"
            }
            if (-not (Test-One2xManifestObject -Manifest $manifest -ExpectedRepository '')) {
                throw '本地更新清单字段不符合要求'
            }
            $offlineExePath = Join-Path $manifestDir ([string]$manifest.exe)
            if (-not (Test-Path -LiteralPath $offlineExePath -PathType Leaf)) {
                throw "找不到本地安装包：$offlineExePath"
            }
        } else {
            if (-not (Test-One2xRepository $Repository)) {
                throw "发行仓库标识无效（若使用未配置默认仓库的候选脚本，请显式传入 -Repository owner/repo）：$Repository"
            }
            Enable-One2xTls
            $script:ActiveWebProxy = Resolve-One2xWebProxy -ExplicitProxy $Proxy
            $manifestUri = [Uri]"https://github.com/$Repository/releases/latest/download/windows-update-x86_64.json"
            $sigUri = [Uri]"https://github.com/$Repository/releases/latest/download/windows-update-x86_64.sig"
            $verified = $false
            for ($pairAttempt = 1; $pairAttempt -le 3; $pairAttempt++) {
                $manifestBytes = Read-One2xSmallAsset -Uri $manifestUri -MaxBytes 16384
                $sigBytes = Read-One2xSmallAsset -Uri $sigUri -MaxBytes 64
                if ([One2xTrajBootstrapSecurity]::VerifyEd25519Strict($manifestBytes, $sigBytes, $script:PinnedReleasePublicKeyPem)) {
                    $manifest = ([System.Text.Encoding]::UTF8.GetString($manifestBytes)) | ConvertFrom-Json
                    $verified = $true
                    break
                }
                if ($pairAttempt -lt 3) {
                    Start-Sleep -Seconds (2 * $pairAttempt)
                }
            }
            if (-not $verified) {
                throw '更新清单 Ed25519 签名校验失败，已中止下载'
            }
            if ($null -ne $manifest -and $manifest.PSObject.Properties.Name -notcontains 'first_install_protocol') {
                throw "当前公开版本 $($manifest.version) 尚未启用安全首装协议（first_install_protocol），请前往 GitHub Releases 页面下载安装包手动安装"
            }
            if (-not (Test-One2xManifestObject -Manifest $manifest -ExpectedRepository $Repository)) {
                throw '更新清单的仓库、平台或安装包信息无效'
            }
        }

        $expectedSize = [long]$manifest.size
        $reserveBytes = Get-One2xDiskReserveBytes
        $requiredBefore = $reserveBytes + (3L * $expectedSize)
        if ((Get-One2xFreeSpaceBytes $programsDir) -lt $requiredBefore) {
            throw '安装盘剩余空间不足，无法在保留录制空间的同时完成首次安装'
        }

        $randBytes = New-Object byte[] 6
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($randBytes) } finally { $rng.Dispose() }
        $suffix = ([BitConverter]::ToString($randBytes)).Replace('-', '').ToLowerInvariant()
        $candidateStage = Join-Path $programsDir ".one2x-traj-bootstrap-$suffix"
        if (Test-Path -LiteralPath $candidateStage) {
            throw "首装暂存目录已存在，已拒绝覆盖：$candidateStage"
        }
        $createdItem = New-Item -ItemType Directory -Path $candidateStage -ErrorAction Stop
        $stageDirPin = [One2xTrajBootstrapSecurity]::LockDirectoryNoRename($candidateStage)
        $stageDir = $candidateStage
        $stageCreatedUtc = $createdItem.CreationTimeUtc

        $stagedExe = Join-Path $stageDir ([string]$manifest.exe)
        $writeStream = [One2xTrajBootstrapSecurity]::CreateNewPrivateFile($stagedExe)
        $stagedExeCreated = $true
        try {
            if ($null -ne $offlineExePath) {
                $srcStream = New-Object System.IO.FileStream(
                    $offlineExePath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read
                )
                try {
                    $buf = New-Object byte[] (64 * 1024)
                    $copied = 0L
                    while ($true) {
                        $n = $srcStream.Read($buf, 0, $buf.Length)
                        if ($n -le 0) { break }
                        $copied += $n
                        if ($copied -gt $expectedSize) {
                            throw '安装程序超过清单规定的大小'
                        }
                        $writeStream.Write($buf, 0, $n)
                    }
                    if ($copied -ne $expectedSize) {
                        throw '安装程序大小与清单不符'
                    }
                    $writeStream.Flush($true)
                } finally {
                    $srcStream.Dispose()
                }
            } else {
                $exeUri = [Uri]"https://github.com/$Repository/releases/download/trajectory-v$($manifest.version)/$($manifest.exe)"
                Write-Host "已验证发行清单 v$($manifest.version)，开始下载 $($manifest.exe)..."
                Receive-One2xInstaller -Uri $exeUri -ExpectedSize $expectedSize -FileStream $writeStream
            }
        } finally {
            $writeStream.Dispose()
        }

        Remove-Item -LiteralPath $stagedExe -Stream Zone.Identifier -ErrorAction SilentlyContinue

        $lockedRead = New-Object System.IO.FileStream(
            $stagedExe,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $proc = $null
        $resultPath = Join-Path $stageDir 'first-install-result.json'
        try {
            $actualSha = [One2xTrajBootstrapSecurity]::ComputeSha256Hex($lockedRead, $expectedSize)
            if (-not $actualSha.Equals(([string]$manifest.sha256).ToLowerInvariant(), [StringComparison]::Ordinal)) {
                throw "安装程序 SHA-256 与签名清单不符（期望 $($manifest.sha256)，实际 $actualSha）"
            }
            if ((Get-One2xFreeSpaceBytes $programsDir) -lt ($reserveBytes + (2L * $expectedSize))) {
                throw '安装盘剩余空间不足，无法在保留录制空间的同时完成首次安装'
            }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $stagedExe
            $psi.WorkingDirectory = $programsDir
            $psi.UseShellExecute = $false
            $escapedResult = '"' + $resultPath.Replace('"', '\"') + '"'
            $psi.Arguments = "--first-install --first-install-result $escapedResult"
            try {
                $proc = [System.Diagnostics.Process]::Start($psi)
            } catch [System.ComponentModel.Win32Exception] {
                $hint = Format-One2xWin32Block -NativeCode $_.Exception.NativeErrorCode -ExeName ([string]$manifest.exe)
                if ($null -ne $hint) { throw $hint }
                throw "无法启动安装程序（Win32 错误 $($_.Exception.NativeErrorCode)）：$($_.Exception.Message)"
            }
            if ($null -eq $proc) {
                throw '安装程序未能启动'
            }
        } finally {
            $lockedRead.Dispose()
        }

        try {
            $proc.WaitForExit()
            $exitCode = $proc.ExitCode
        } finally {
            $proc.Dispose()
        }

        $resultObj = $null
        if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
            try {
                $resultObj = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {}
        }
        $expectedStatus = switch ($exitCode) {
            0 { 'installed' }
            10 { 'already_current' }
            11 { 'needs_tray_update' }
            12 { 'blocked' }
            default { 'error' }
        }
        $hasValidReceipt = (
            $null -ne $resultObj -and
            $null -ne $resultObj.PSObject.Properties['exit_code'] -and
            $null -ne $resultObj.exit_code -and
            ($resultObj.exit_code -is [int] -or $resultObj.exit_code -is [long]) -and
            ([long]$resultObj.exit_code -eq [long]$exitCode) -and
            ([string]$resultObj.status -ceq $expectedStatus) -and
            ([string]$resultObj.package_version -ceq [string]$manifest.version)
        )
        $msg = if ($hasValidReceipt -and -not [string]::IsNullOrEmpty([string]$resultObj.message)) {
            [string]$resultObj.message
        } else {
            ''
        }

        switch ($exitCode) {
            0 {
                if (-not $hasValidReceipt) {
                    throw '安装程序未返回有效的首装完成回执，请检查安装状态或联系轨迹采集负责人。'
                }
                Write-Host ($(if ($msg) { $msg } else { "已安装 one2x 轨迹记录 $($manifest.version)，请在弹出的窗口确认采集说明。" }))
                return
            }
            10 {
                if (-not $hasValidReceipt) {
                    throw '安装程序未返回有效的版本核验回执，请检查安装状态或联系轨迹采集负责人。'
                }
                Write-Host ($(if ($msg) { $msg } else { "本机已安装相同或更高版本，无需重新安装。" }))
                return
            }
            11 {
                throw ($(if ($msg) { $msg } else { "检测到本机已安装旧版（待装版本 $($manifest.version)），请使用右下角托盘菜单「检查更新」安全升级。" }))
            }
            12 {
                throw ($(if ($msg) { $msg } else { "one2x 轨迹记录被 Windows 安全策略拦截（智能应用控制：$(Get-One2xSacContext)），请联系轨迹采集负责人。" }))
            }
            default {
                throw ($(if ($msg) { $msg } else { "安装程序异常退出（退出码 $exitCode），请查看 %USERPROFILE%\.traj\app.log 或联系轨迹采集负责人。" }))
            }
        }
    } finally {
        if ($null -ne $stageDir -and $null -ne $stageDirPin -and -not $stageDirPin.IsInvalid) {
            $filesToClean = @()
            if ($stagedExeCreated -and $null -ne $stagedExe) { $filesToClean += $stagedExe }
            if ($null -ne $resultPath) { $filesToClean += $resultPath }
            for ($i = 0; $i -lt 10; $i++) {
                $remaining = 0
                foreach ($knownFile in $filesToClean) {
                    if (Test-Path -LiteralPath $knownFile -PathType Leaf) {
                        $fItem = Get-Item -LiteralPath $knownFile -Force -ErrorAction SilentlyContinue
                        if ($null -ne $fItem -and (($fItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0)) {
                            Remove-Item -LiteralPath $knownFile -Force -ErrorAction SilentlyContinue
                        }
                        if (Test-Path -LiteralPath $knownFile) { $remaining++ }
                    }
                }
                if ($remaining -eq 0) { break }
                Start-Sleep -Milliseconds 300
            }
            $stageDirPin.Dispose()
            $stageDirPin = $null
            $stageItem = Get-Item -LiteralPath $stageDir -Force -ErrorAction SilentlyContinue
            if ($null -ne $stageItem -and (($stageItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) -and $stageItem.CreationTimeUtc -eq $stageCreatedUtc) {
                try {
                    [System.IO.Directory]::Delete($stageDir, $false)
                } catch {}
            }
        } elseif ($null -ne $stageDirPin) {
            $stageDirPin.Dispose()
        }
        if ($null -ne $bootstrapLock) {
            $bootstrapLock.Dispose()
        }
    }
}

if (-not $LoadHelpersOnly) {
    Invoke-One2xTrajBootstrap
}
