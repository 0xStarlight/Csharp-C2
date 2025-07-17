using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using TeamServer;

namespace ApiTests
{
    public abstract class ApiTest
    {
        protected HttpClient Client;

        protected ApiTest()
        {
            var factory = new WebApplicationFactory<Startup>();
            Client = factory.CreateClient();
        }
    }
}
