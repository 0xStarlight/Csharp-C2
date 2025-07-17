using Agent.Models;

namespace Agent.Commands
{
    public class TestCommand : AgentCommand
    {
        public override string Name => "TestCommand";

        public override string Execute(AgentTask task)
        {
            return "Hello from Test Command";
        }
    }
}
