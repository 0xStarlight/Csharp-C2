using Agent.Models;

using System.Security.Principal;

namespace Agent.Commands
{
    public class WhoAmI : AgentCommand
    {
        public override string Name => "whoami";

        public override string Execute(AgentTask task)
        {
            var identity = WindowsIdentity.GetCurrent();
            return identity.Name;
        }
    }
}
