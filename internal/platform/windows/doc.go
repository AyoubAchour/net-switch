// Package winplatform implements the Windows boundary in bounded read workers.
// The existing helper's meter, network, outside and quick-probe implementation
// is folded here; new operations call Windows APIs without a scripting host.
//
// Reference model (API contracts and lifetime/ABI study, not copied code):
//   - Microsoft GetAdaptersAddresses / GetIpForwardTable2 / SetIpInterfaceEntry:
//     https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
//   - Microsoft's MSFT_NetIPInterface.cdxml: PolicyStore is a query option.
//     The COM provider persists metrics; SetIpInterfaceEntry changes live state.
//   - SetNamedSecurityInfo and reparse-point handles:
//     https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow
//   - GetExtendedTcpTable, SetTcpEntry and GetProcessTimes:
//     https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module
//   - IDispatch/EXCEPINFO, Task Scheduler and IShellLinkW:
//     https://learn.microsoft.com/windows/win32/api/oaidl/ns-oaidl-excepinfo
//   - ExtractAssociatedIcon, GetIconInfo, GetDIBits and VerQueryValue:
//     https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-extractassociatediconw
//   - x/sys/windows, WireGuard winipcfg, Tailscale winutil/startupinfo and s4u,
//     and .NET Icon.ToBitmap were studied for ownership and calling conventions.
//
// Start-menu and icon work uses the current interactive user's profile in
// milestone one. A LocalSystem service must delegate that work to the enrolled
// user's desktop process instead of reading the service account's profile.
package winplatform
