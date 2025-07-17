using Microsoft.Extensions.DependencyInjection;

using TeamServer.Services;

namespace TeamServer.UnitTests
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IListenerService, ListenerService>();
            services.AddSingleton<IAgentService, AgentService>();
        }
    }
}
