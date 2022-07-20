/// https://twitter.com/philiptsukerman/status/1541408069510479874
/// "You have event 14 for registrations and event 16 for bindings,
///  with an ActivityId GUID thingy to correlate."


// This utility collects RPC binding details in real-time.
//
// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
// An ETW AutoLogger session would allow complete system profiling.
// However, the volume of non-interesting RPC events may be prohibitive as
// Keyword filtering is not available for this provider and AutoLoggers
// do not seem to support modern EVENT_FILTER_TYPE_EVENT_ID filters.

using Microsoft.O365.Security.ETW;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace RpcRegistrationMonitor {
    class Program {
        static void Main() {
            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator) != true) {
                Console.WriteLine("[ERROR] This program must be run as Administrator");
                // admin is required for Microsoft-Windows-Kernel-Process ETW events which we use to resolve modules in call stacks
                return;
            }

            var trace = new UserTrace("RpcRegistrationMonitor");

            var registrationMap = new Dictionary<uint, Dictionary<Guid, SortedSet<string>>>();
            var bindings = new SortedSet<string>();

            ////////////////////////////////////////////////////////////////////////////////
            // Microsoft-Windows-RPC
            var rpcProvider = new Provider("Microsoft-Windows-RPC") {
                Level = 4,
                TraceFlags = TraceFlags.IncludeStackTrace
            };

            var registrationFilter = new EventFilter(Filter.EventIdIs(14));
            registrationFilter.OnEvent += (record) => {
                var InterfaceUuid = new Guid(record.GetBinary("InterfaceUuid"));
                var TypeMgrUuid = new Guid(record.GetBinary("TypeMgrUuid"));
                var Flags = $"{(RpcInterfaceFlags)record.GetUInt32("Flags")}".Replace(", ","|");
                var SD = (record.GetUInt32("SDSize") == 0) ? "" : new RawSecurityDescriptor(record.GetBinary("SD"), 0).GetSddlForm(AccessControlSections.All);

                var typeManager = (TypeMgrUuid == Guid.Empty) ? "" : $"{TypeMgrUuid}";
                var callingModule = CallingModule(record);
                if (callingModule == null) {
                    Console.WriteLine($"[WARNING] Could not determine module for {InterfaceUuid}");
                } else {
                    if (!registrationMap.ContainsKey(record.ProcessId)) {
                        registrationMap[record.ProcessId] = new Dictionary<Guid, SortedSet<string>>();
                    }

                    if (!registrationMap[record.ProcessId].ContainsKey(record.ActivityId)) {
                        registrationMap[record.ProcessId][record.ActivityId] = new SortedSet<string>();
                    }

                    // WARNING: ActivityId is per RPC activity - which could contain multiple interface registrations.
                    // We currently correlate bindings with *all* registrations for a given activity.
                    var registration = $"{callingModule},{InterfaceUuid},{typeManager},{Flags},{SD}";
                    registrationMap[record.ProcessId][record.ActivityId].Add(registration);
                }
            };

            var bindingFilter = new EventFilter(Filter.EventIdIs(16));
            bindingFilter.OnEvent += (record) => {
                var Protocol = record.GetUnicodeString("Protocol");
                var Endpoint = record.GetUnicodeString("Endpoint");
                if (string.IsNullOrEmpty(Endpoint) || Endpoint == "NULL") {
                    Endpoint = record.GetUnicodeString("NetworkAddress");
                }
                var PendingQueueSize = record.GetUInt32("PendingQueueSize");
                var EndpointFlags = record.GetUInt32("EndpointFlags");
                var NicFlags = record.GetUInt32("NicFlags");

                if(registrationMap.ContainsKey(record.ProcessId) && registrationMap[record.ProcessId].ContainsKey(record.ActivityId)) {
                    foreach (var registration in registrationMap[record.ProcessId][record.ActivityId]) {
                        var binding = $"{registration},{Protocol},{Endpoint},{EndpointFlags},{NicFlags},{PendingQueueSize}";
                        if (!bindings.Contains(binding)) {
                            bindings.Add(binding);
                            Console.WriteLine($"[Binding] {binding}");
                        }
                    }
                }
            };

            rpcProvider.AddFilter(registrationFilter);
            rpcProvider.AddFilter(bindingFilter);
            trace.Enable(rpcProvider);

            ////////////////////////////////////////////////////////////////////////////////
            // Microsoft-Windows-Kernel-Process
            var processProvider = new Provider("Microsoft-Windows-Kernel-Process") {
                Any = 0x10 | 0x40 // WINEVENT_KEYWORD_PROCESS | WINEVENT_KEYWORD_IMAGE
            };

            // Event 5 - ImageLoad
            var imageLoadFilter = new EventFilter(Filter.EventIdIs(5));
            imageLoadFilter.OnEvent += (record) => {
                var ProcessID = record.GetUInt32("ProcessID");
                var ImageBase = record.GetUInt64("ImageBase");
                var ImageSize = record.GetUInt64("ImageSize");
                var ImageName = Regex.Replace(record.GetUnicodeString("ImageName"), @"^\\Device\\HarddiskVolume[0-9]+", "");

                if (IsInSystemImageRange(ImageBase)) {
                    for (var va = ImageBase; va < ImageBase + ImageSize; va += 64 * 1024) {
                        _SharedDllMap[va] = ImageName;
                    }
                } else {
                    if (!_LocalImageMap.ContainsKey(ProcessID)) {
                        _LocalImageMap[ProcessID] = new Dictionary<UInt64, string>();
                    }

                    for (var va = ImageBase; va < ImageBase + ImageSize; va += 64 * 1024) {
                        _LocalImageMap[ProcessID][va] = ImageName;
                    }
                }
            };

            // Event 2 - ProcessStop
            var processStopFilter = new EventFilter(Filter.EventIdIs(2));
            processStopFilter.OnEvent += (record) => {
                registrationMap.Remove(record.ProcessId);
                _LocalImageMap.Remove(record.ProcessId);
            };

            processProvider.AddFilter(imageLoadFilter);
            processProvider.AddFilter(processStopFilter);
            trace.Enable(processProvider);

            Console.CancelKeyPress += delegate {
                if (bindings.Count != 0) {
                    var rpcBindingsFilename = "rpc_bindings.txt";
                    File.Delete(rpcBindingsFilename);
                    File.AppendAllText(rpcBindingsFilename, "Module,Interface UUID,Type Manager,Registration Flags,Security Descriptor,Protocol,Endpoint,EndpointFlags,NicFlags,PendingQueueSize");
                    File.AppendAllLines(rpcBindingsFilename, bindings);
                    Console.WriteLine($"Wrote {bindings.Count} RPC bindings to {new FileInfo(rpcBindingsFilename).FullName}");
                }

                trace.Stop();
            };


            Console.WriteLine($"ETW tracing started. Press Ctrl-C to stop.");
            trace.Start();

            Console.WriteLine($"ETW tracing stopped. Found {bindings.Count} RPC bindings");
        }

        // rpcdce.h
        [Flags]
        enum RpcInterfaceFlags : UInt32 {
            AUTOLISTEN                   = 0x0001,
            OLE                          = 0x0002,
            ALLOW_UNKNOWN_AUTHORITY      = 0x0004,
            ALLOW_SECURE_ONLY            = 0x0008,
            ALLOW_CALLBACKS_WITH_NO_AUTH = 0x0010,
            ALLOW_LOCAL_ONLY             = 0x0020,
            SEC_NO_CACHE                 = 0x0040,
            SEC_CACHE_PER_PROC           = 0x0080,
            ASYNC_CALLBACK               = 0x0100
        }

        // The kernel preferentially uses these two ranges to load DLLs at shared addresses
        internal static bool IsInSystemImageRange(UInt64 address) {
            return ((address >= 0x7FF800000000) && (address < 0x7FFFFFFF0000)) || ((address >= 0x50000000) && (address < 0x78000000));
        }

        // A map of the 64KB regions allocated to shared DLLs
        private static readonly Dictionary<UInt64, string> _SharedDllMap = new();

        // A per-process map of the 64KB regions allocated to other loaded images.
        // Typically the executable (though this can be shared in special cases) and any DLLs unable to be loaded at the preferred shared address.
        private static readonly Dictionary<uint, Dictionary<UInt64, string>> _LocalImageMap = new();

        private static string? Module(uint pid, UInt64 address) {
            address &= ~0xFFFFul; // align to default allocation granularity (64K)

            if (IsInSystemImageRange(address) && _SharedDllMap.ContainsKey(address))
                return _SharedDllMap[address];

            if (_LocalImageMap.ContainsKey(pid) && _LocalImageMap[pid].ContainsKey(address))
                return _LocalImageMap[pid][address];

            // This could be a module loaded before we started, or a call from private memory such as JIT or shellcode.
            return null;
        }

        // A list of modules to ignore when searching a call stack for callers to RPC functions.
        private static readonly List<string> apiModules = new() { "ntdll", "rpcrt4", "wow64", "wow64cpu"};

        private static string? CallingModule(IEventRecord record) {
            foreach (var returnAddress in record.GetStackTrace().Select(x => x.ToUInt64())) {
                var callingModule = Module(record.ProcessId, returnAddress);
                if (apiModules.Contains(Path.GetFileNameWithoutExtension(callingModule)))
                    continue; // skip

                return callingModule;
            }

            // Occassionally ETW includes empty call stacks.
            return null;
        }
    }
}
