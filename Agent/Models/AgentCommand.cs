namespace Agent.Models
{
    public abstract class AgentCommand
    {
        public abstract string Name { get; }

        public abstract string Execute(AgentTask task);
    }
}
