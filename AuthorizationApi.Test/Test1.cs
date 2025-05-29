using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using AuthorizationApi.Controllers;
using AuthorizationApi.Model;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using System;

namespace AuthorizationApi.Tests
{
    [TestClass]
    public class AuthControllerTests
    {
        private Mock<ILogger<AuthController>> _loggerMock;
        private Mock<IConfiguration> _configMock;
        private Mock<IHttpClientFactory> _clientFactoryMock;
        private AuthController _controller;

        [TestInitialize]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<AuthController>>();
            _configMock = new Mock<IConfiguration>();
            _clientFactoryMock = new Mock<IHttpClientFactory>();

            _controller = new AuthController(_loggerMock.Object, _configMock.Object, _clientFactoryMock.Object);
        }

        [TestMethod]
        public async Task UserLogin_ReturnsOk_WhenLoginSuccessful()
        {
            // Arrange
            var login = new Login { EmailAddress = "test@example.com", Password = "password123" };
            var fakeResponse = new Response { id = "123", loginResult = "true" };

            var httpMessageHandler = new MockHttpMessageHandler(JsonSerializer.Serialize(fakeResponse), HttpStatusCode.OK);
            var client = new HttpClient(httpMessageHandler) { BaseAddress = new Uri("http://localhost") };

            _clientFactoryMock.Setup(_ => _.CreateClient("gateway")).Returns(client);

            // Act
            var result = await _controller.UserLogin(login);

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
        }

        [TestMethod]
        public async Task UserLogin_ReturnsUnauthorized_WhenLoginFails()
        {
            var login = new Login { EmailAddress = "test@example.com", Password = "wrong" };
            var fakeResponse = new Response { id = "", loginResult = "false" };

            var httpMessageHandler = new MockHttpMessageHandler(JsonSerializer.Serialize(fakeResponse), HttpStatusCode.OK);
            var client = new HttpClient(httpMessageHandler) { BaseAddress = new Uri("http://localhost") };

            _clientFactoryMock.Setup(_ => _.CreateClient("gateway")).Returns(client);

            var result = await _controller.UserLogin(login);

            Assert.IsInstanceOfType(result, typeof(UnauthorizedObjectResult));
        }

        [TestMethod]
        public async Task AdminLogin_ReturnsOk_WhenPasswordIsCorrect()
        {
            var login = new Login { EmailAddress = "admin@example.com", Password = "secret" };

            _configMock.Setup(c => c["VaultName"]).Returns("http://localhost:8200");

            var controller = new Mock<AuthController>(_loggerMock.Object, _configMock.Object, _clientFactoryMock.Object) { CallBase = true };
            controller.Setup(x => x.GetSecret(It.IsAny<Login>(), It.IsAny<IConfiguration>())).ReturnsAsync("secret");

            var result = await controller.Object.AdminLogin(login);

            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
        }

        [TestMethod]
        public async Task AdminLogin_ReturnsUnauthorized_WhenPasswordIsIncorrect()
        {
            var login = new Login { EmailAddress = "admin@example.com", Password = "wrong" };

            _configMock.Setup(c => c["VaultName"]).Returns("http://localhost:8200");

            var controller = new Mock<AuthController>(_loggerMock.Object, _configMock.Object, _clientFactoryMock.Object) { CallBase = true };
            controller.Setup(x => x.GetSecret(It.IsAny<Login>(), It.IsAny<IConfiguration>())).ReturnsAsync("secret");

            var result = await controller.Object.AdminLogin(login);

            Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
        }

    }

    public class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _response;
        private readonly HttpStatusCode _statusCode;

        public MockHttpMessageHandler(string response, HttpStatusCode statusCode)
        {
            _response = response;
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage
            {
                StatusCode = _statusCode,
                Content = new StringContent(_response, System.Text.Encoding.UTF8, "application/json")
            });
        }
    }
}
