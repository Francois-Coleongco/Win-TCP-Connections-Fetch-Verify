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

    private ushort Ntoh(uint netshort)
    {
        return (ushort)(((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8));
    }

    public Dictionary<string, TcpConnection> GetTcpConnections() {
        IntPtr tcpTablePtr = IntPtr.Zero;
        int dwOutBufLen = 0;
        bool sort = true;
        int ipVersion = AF_INET; // AF_INET for IPv4
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
            _connections[$"{conn.LocalAddress}:{conn.LocalPort}"] = conn;

        }

        return _connections;
    }
    public void PrintTcpConnections()
    {
        foreach (var conn in _connections.Values)
        {
            Console.WriteLine($"Local: {conn.LocalAddress}:{conn.LocalPort}, Remote: {conn.RemoteAddress}:{conn.RemotePort}, State: {conn.State}, PID: {conn.ProcessId}");
        }
    }

}
class Fetch
{

    // Main Method
    public static void Main()
    {
        FetchConns fetchConns = new FetchConns();

        fetchConns.PrintTcpConnections();
        Console.WriteLine("Should show no connectiosn at tions point because of empty dicitonary");
        fetchConns.GetTcpConnections();
        fetchConns.PrintTcpConnections();
        Console.WriteLine("Should show connections now because of filled dictionary");
    }
}