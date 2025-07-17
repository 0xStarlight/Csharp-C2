using Agent.Models;

using System.Linq;

namespace Agent.Commands
{
    public class Run : AgentCommand
    {
        public override string Name => "run";

        public override string Execute(AgentTask task)
        {
            var fileName = task.Arguments[0];
            var args = string.Join(" ", task.Arguments.Skip(1));

            return Internal.Execute.ExecuteCommand(fileName, args);
        }
    }
}
