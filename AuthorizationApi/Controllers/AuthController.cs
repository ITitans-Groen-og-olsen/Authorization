using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthorizationApi.Model;
namespace AuthorizationApi.Controllers;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using MongoDB.Bson;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _clientFactory;

    // Constructor to inject dependencies: logging, configuration, and HTTP client factory
    public AuthController(ILogger<AuthController> logger, IConfiguration config, IHttpClientFactory clientFactory)
    {
        _config = config;
        _logger = logger;
        _clientFactory = clientFactory;
    }
    // Generates a JWT token for a user/admin
    private string GenerateJwtToken(string email, string role)
    {
        // Create security key using environment variable (or fallback key)
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("Secret") ?? "this-is-thefallback-key-which-is-at-least-128-bits"));

        // Generate signing credentials using HMAC SHA256 algorithm
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // Define claims: email and user role
        var claims = new[]
        {
        new Claim(ClaimTypes.NameIdentifier, email),
        new Claim(ClaimTypes.Role, role)
    };

        // Create the token with issuer, audience, claims, expiration, and signing credentials
        var token = new JwtSecurityToken(
            issuer: Environment.GetEnvironmentVariable("Issuer") ?? "none",
            audience: "http://localhost",
            claims: claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }


    [AllowAnonymous]
    [HttpPost("UserLogin")]
    public async Task<IActionResult> UserLogin([FromBody] Login login)
    {
         // Create an HTTP client for calling the external gateway API
        var client = _clientFactory.CreateClient("gateway");
        var endpoint = "/User/login";
        string role = "User";
        
        // Post that uses the login method inside the userService to validate login credential
        var response = await client.PostAsJsonAsync(endpoint, login);
        Console.WriteLine($"response was {response}");
        
        var content = await response.Content.ReadFromJsonAsync<Response>();
        Console.WriteLine($"The content is {content}");
        ResponseObject responseObject = new();

        // If login is successful, generate a token and return i
        if (content.loginResult == "true")
        {
            var token = GenerateJwtToken(login.EmailAddress, role);
            responseObject.id = content.id;
            responseObject.jwtToken = token;
            return Ok(responseObject);
        }
        // If login fails return Unauthorized
        return Unauthorized(responseObject);
    }

    [AllowAnonymous]
    [HttpPost("AdminLogin")]
    public async Task<IActionResult> AdminLogin([FromBody] Login login)
    {
        string role = "Admin";
        // Retrieve the secret (admin password) from HashiCorp Vault
        var secret = await GetSecret(login, _config);

        // Check if the password matches the secret
        if (login.Password == secret.ToString())
        {
            var token = GenerateJwtToken(login.EmailAddress, role);
            return Ok(new { token });
        }
        // If login fails return Unauthorized
        return Unauthorized();
    }

    // Retrieves password from Vault based on admin email
    protected virtual async Task<string> GetSecret(Login login, IConfiguration config)
    {
        var endPoint = config["VaultName"] ?? "<blank>";

        // Accept all SSL certificates
        var httpClientHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
        };

        // Configure Vault authentication using a static token
        IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

        // Configure Vault authentication using a static token
        var vaultClientSettings = new VaultClientSettings(endPoint, authMethod)
        {
            Namespace = "",
            MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
            {
                BaseAddress = new Uri(endPoint)
            }
        };

        IVaultClient vaultClient = new VaultClient(vaultClientSettings);

        // Use client to read a key-value secret.
        try
        {
            Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2
                .ReadSecretAsync(path: "passwords", mountPoint: "secret");

            var minkode = kv2Secret.Data.Data[login.EmailAddress];

            return minkode.ToString();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving secret from Vault");
            return string.Empty;
        }
    }
}

// DataTransferObject for login response from userService
public class Response
{
    public string id { get; set; }
    public string loginResult { get; set; }
}
// Object returned to client on successful login
// Used to transfer userId and JwtToken
public class ResponseObject
{
    public string id { get; set; }
    public string jwtToken { get; set; }
}
