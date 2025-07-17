using Agent.Models;

using System.IO;

namespace Agent.Commands
{
    public class PrintWorkingDirectory : AgentCommand
    {
        public override string Name => "pwd";

        public override string Execute(AgentTask task)
        {
            return Directory.GetCurrentDirectory();
        }
    }
}
