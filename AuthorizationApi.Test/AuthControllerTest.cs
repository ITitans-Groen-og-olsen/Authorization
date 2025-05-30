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
using System;
using Moq.Protected;

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

            // Mock JWT token settings
            _configMock.Setup(c => c["Jwt:Key"]).Returns("ThisIsASecretKeyThatIsAtLeast128Bits!");
            _configMock.Setup(c => c["Jwt:Issuer"]).Returns("TestIssuer");
            _configMock.Setup(c => c["Jwt:Audience"]).Returns("http://localhost");

            _controller = new AuthController(_loggerMock.Object, _configMock.Object, _clientFactoryMock.Object);
        }

[TestMethod]
public async Task UserLogin_ReturnsOk_WhenLoginSuccessful()
{
    // Arrange
    var logger = new Mock<ILogger<AuthController>>();
    var config = new ConfigurationBuilder().Build(); // or a mock if needed

    var responseJson = JsonSerializer.Serialize(new Response
    {
        id = "test-id",
        loginResult = "true"
    });

    var mockHandler = new MockHttpMessageHandler(responseJson, HttpStatusCode.OK);
    var client = new HttpClient(mockHandler)
    {
        BaseAddress = new Uri("http://localhost") // make sure it matches your controller expectation
    };

    var mockFactory = new Mock<IHttpClientFactory>();
    mockFactory.Setup(f => f.CreateClient("gateway")).Returns(client);

    var controller = new AuthController(logger.Object, config, mockFactory.Object);

    var login = new Login
    {
        EmailAddress = "test@example.com",
        Password = "any-password"
    };

    // Act
    var result = await controller.UserLogin(login);

    // Assert
    var okResult = result as OkObjectResult;
    Assert.IsNotNull(okResult);
    Assert.AreEqual(200, okResult.StatusCode);

    var responseObject = okResult.Value as ResponseObject;
    Assert.IsNotNull(responseObject);
    Assert.AreEqual("test-id", responseObject.id);
    Assert.IsFalse(string.IsNullOrEmpty(responseObject.jwtToken));
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
    // Arrange
    _configMock.Setup(c => c["VaultName"]).Returns("http://localhost:8200");

    var controllerMock = new Mock<AuthController>(_loggerMock.Object, _configMock.Object, _clientFactoryMock.Object)
    {
        CallBase = true
    };

    controllerMock
    .Protected()
    .Setup<Task<string>>("GetSecret", ItExpr.IsAny<Login>(), ItExpr.IsAny<IConfiguration>())
    .ReturnsAsync("correct-password");

var login = new Login { EmailAddress = "admin@example.com", Password = "expected-secret" };

controllerMock
    .Protected()
    .Setup<Task<string>>("GetSecret", login, _configMock.Object)
    .ReturnsAsync(login.Password); // ensures it always matches

    // Act
    var result = await controllerMock.Object.AdminLogin(login);

    // Assert
    Assert.IsInstanceOfType(result, typeof(OkObjectResult));
}


        [TestMethod]
public async Task AdminLogin_ReturnsUnauthorized_WhenPasswordIsIncorrect()
{
    // Arrange
    var login = new Login { EmailAddress = "admin@example.com", Password = "wrong" };

    _configMock.Setup(c => c["VaultName"]).Returns("http://localhost:8200");

    var controllerMock = new Mock<AuthController>(_loggerMock.Object, _configMock.Object, _clientFactoryMock.Object)
    {
        CallBase = true
    };

    controllerMock
    .Protected()
    .Setup<Task<string>>("GetSecret", ItExpr.IsAny<Login>(), ItExpr.IsAny<IConfiguration>())
    .ReturnsAsync("secret"); // Simulate the correct secret in vault

    // Act
    var result = await controllerMock.Object.AdminLogin(login);

    // Assert
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
