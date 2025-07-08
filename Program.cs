// See https://aka.ms/new-console-template for more information

using System.Runtime.InteropServices;
public class TcpConnection
{
    public string LocalAddress { get; set; }
    public ushort LocalPort { get; set; }
    public string RemoteAddress { get; set; }
    public ushort RemotePort { get; set; }
    public string State { get; set; }
    public int ProcessId { get; set; }
    public string ProcessName { get; set; }
}
public class FetchConns
{
    FetchConns() {
        _httpClient.DefaultRequestHeaders.Add("Key", "MYKEY SHOULD BE PASSED BY THE USER INTO THE PROGRAM AND THEY CAN CHOOSE IT TO BE SAVED TO CONFIGURATION FOR SUBSEQUENT APPLICATION BOOTS"); // Replace with your actual API key
    }

    public const int AF_INET = 2;

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public MIB_TCPROW_OWNER_PID table;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TCP_TABLE_CLASS tblClass,
        uint reserved);

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    private Dictionary<string, TcpConnection> _connections = new Dictionary<string, TcpConnection>();

    HttpClient _httpClient = new HttpClient();

    private ushort Ntoh(uint netshort)
    {
        return (ushort)(((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8));
    }

    public Dictionary<string, TcpConnection> GetTcpConnections() {
        IntPtr tcpTablePtr = IntPtr.Zero;
        int dwOutBufLen = 0;
        bool sort = true;
        int ipVersion = AF_INET;
        TCP_TABLE_CLASS tblClass = TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS;
        uint reserved = 0;


        uint stat = GetExtendedTcpTable(tcpTablePtr, ref dwOutBufLen, sort, ipVersion, tblClass, reserved);

        tcpTablePtr = Marshal.AllocHGlobal(dwOutBufLen);

        Console.WriteLine("size_of_table " + dwOutBufLen);

        uint result = GetExtendedTcpTable(tcpTablePtr, ref dwOutBufLen, sort, ipVersion, tblClass, reserved);

        if (result != 0)
        {
            Console.WriteLine("Error retrieving TCP connections: " + result);
            return _connections;
        }

        int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
        int numEntries = Marshal.ReadInt32(tcpTablePtr);
        IntPtr currentRowPtr = IntPtr.Add(tcpTablePtr, sizeof(int));
       
        

        for (int i = 0; i < numEntries; i++, currentRowPtr = IntPtr.Add(currentRowPtr, rowSize))
        {
            MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(currentRowPtr);
            TcpConnection conn = new TcpConnection
            {
                LocalAddress = new System.Net.IPAddress(BitConverter.GetBytes(row.localAddr)).ToString(),
                LocalPort = Ntoh(row.localPort),
                RemoteAddress = new System.Net.IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString(),
                RemotePort = Ntoh(row.remotePort),
                State = row.state.ToString(),
                ProcessId = (int)row.owningPid
            };
            _connections[$"{conn.LocalAddress}:{conn.LocalPort}"] = conn; // keep this as the local because you could have multiple connections to the same remote address and port

        }

        return _connections;
    }

    private async Task VerifyIPAddress(string RemoteIP, List<string> badConns)
    {
        Console.WriteLine($"Verifying IP Address: {RemoteIP}");
        await Task.Delay(1000);
        bool api_res = false;

        await _httpClient.GetAsync($"https://api.abuseipdb.com/api/v2/check?ipAddress={RemoteIP}").ContinueWith(response =>
        {
            if (response.IsCompletedSuccessfully && response.Result.IsSuccessStatusCode)
            {
                var content = response.Result.Content.ReadAsStringAsync().Result;
                write content to a file for logging purposes
                api_res = true;
            }
            else
            {
                Console.WriteLine($"Failed to verify IP Address {RemoteIP}: {response.Result.StatusCode}");
            }
        });

        if (!api_res)
        {
            Console.WriteLine($"IP Address {RemoteIP} is INVALID or has issues.");
            badConns.Add($"{RemoteIP}");
        } else
        {
            Console.WriteLine($"IP Address {RemoteIP} VALID and has no issues.");
        }
    }

    public List<string> VerifyAllIPAddresses()
    {
        List<string> badIPs = [];
        HashSet<string> seenIPs = new HashSet<string>();
        List<Task> IPVerifications = [];

        foreach (var conn in _connections.Values)
        {
            if (seenIPs.Contains(conn.RemoteAddress))
            {
                Console.WriteLine($"IP Address {conn.RemoteAddress} has already been seen. Skipping verification.");
                continue;
            }
            Task t = VerifyIPAddress(conn.RemoteAddress, badIPs);
            IPVerifications.Add(t);
            seenIPs.Add(conn.RemoteAddress);
        }

        Task.WaitAll(IPVerifications);

        return badIPs;
    }


    public void PrintTcpConnections()
    {
        foreach (var conn in _connections.Values)
        {
            Console.WriteLine($"Local: {conn.LocalAddress}:{conn.LocalPort}, Remote: {conn.RemoteAddress}:{conn.RemotePort}, State: {conn.State}, PID: {conn.ProcessId}");
        }
    }

}

// WHEN VERIFYING THE IP ADDRESSES YOUCAN PUT CHECKED IP ADDRESSES IN A MEMO TO ENSURE SEEN IP ADDRESSES ARE NOT PROCESSED IN THE API CALLS TO VirusTotal/ABUSEIPDB. That way, you never exceed the daily count
// PERHAPS USE ABUSEIPDB FOR IP ADDRESS CHECKING BECAUSE IT DOESN'T HAVE A BY THE MINUTE RATE LIMIT LIKE VIRUSTOTAL DOES.

class Fetch
{

    // Main Method
    public static void Main()
    {
        FetchConns fetchConns = new FetchConns();

        fetchConns.PrintTcpConnections();
        Console.WriteLine("Should show NOOOO connections at this point because of empty dicitonary");
        fetchConns.GetTcpConnections();
        fetchConns.PrintTcpConnections();
        Console.WriteLine("Should show SOMEEEEE connections now because of filled dictionary");
        List<string> badIPs = fetchConns.VerifyAllIPAddresses();
        Console.WriteLine("Finished verifying all IP addresses, this is what they were: ");
        foreach (var ip in badIPs)
        {
            Console.WriteLine(ip);
        }
    }
}