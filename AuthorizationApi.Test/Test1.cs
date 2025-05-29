using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Moq;
using AuthorizationApi.Controllers;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthorizationApi.Model;

namespace AuthServiceTests
{
    [TestClass]
    public class AuthControllerTests
    {
        private AuthController _controller;
        private Mock<ILogger<AuthController>> _loggerMock;
        private Mock<IConfiguration> _configMock;

        [TestInitialize]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<AuthController>>();
            _configMock = new Mock<IConfiguration>();

            // Configure secrets
            _configMock.Setup(c => c["Secret"]).Returns("supersecretkey_supersecretkey"); // 32+ chars for HMAC
            _configMock.Setup(c => c["Issuer"]).Returns("TestIssuer");

            _controller = new AuthController(_loggerMock.Object, _configMock.Object);
        }

        [TestMethod]
        public async Task Login_WithValidCredentials_ReturnsToken()
        {
            // Arrange
            var loginModel = new Login
            {
                EmailAddress = "haavy_user",
                Password = "aaakodeord"
            };

            // Act
            var result = await _controller.Login(loginModel);

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
            var okResult = result as OkObjectResult;

            Assert.IsNotNull(okResult?.Value);
            var tokenObj = okResult.Value.GetType().GetProperty("token")?.GetValue(okResult.Value, null);
            Assert.IsInstanceOfType(tokenObj, typeof(string));
            Assert.IsFalse(string.IsNullOrEmpty(tokenObj as string));
        }

        [TestMethod]
        public async Task Login_WithInvalidCredentials_ReturnsUnauthorized()
        {
            // Arrange
            var loginModel = new Login
            {
                EmailAddress = "invalid_user",
                Password = "wrong_pass"
            };

            // Act
            var result = await _controller.Login(loginModel);

            // Assert
            Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
        }
    }
}
