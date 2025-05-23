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

    public AuthController(ILogger<AuthController> logger, IConfiguration config, IHttpClientFactory clientFactory)
    {
        _config = config;
        _logger = logger;
        _clientFactory = clientFactory;
    }
    private string GenerateJwtToken(string email, string role)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("Secret") ?? "none"));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
        new Claim(ClaimTypes.NameIdentifier, email),
        new Claim(ClaimTypes.Role, role)
    };

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
        var client = _clientFactory.CreateClient("gateway");
        var endpoint = "/User/login";
        string role = "User";
        var response = await client.PostAsJsonAsync(endpoint, login);
        Console.WriteLine($"response was {response}");
        var content = await response.Content.ReadFromJsonAsync<Response>();
        Console.WriteLine($"The content is {content}");
        if (content.loginResult == "true")
        {
            var token = GenerateJwtToken(login.EmailAddress, role);

            var returnObject = new
            {
                id = content.id,
                jwtToken = token

            };
           
            return Ok(new { returnObject });
        }
        return Unauthorized();
    }

    [AllowAnonymous]
    [HttpPost("AdminLogin")]
    public async Task<IActionResult> AdminLogin([FromBody] Login login)
    {
        string role = "Admin";
        var secret = await GetSecret(login, _config);
        if (login.Password == secret.ToString())
        {
            var token = GenerateJwtToken(login.EmailAddress, role);
            return Ok(new { token });
        }
        return Unauthorized();
    }

    [AllowAnonymous]
    [HttpGet("GetAnon")]
    public async Task<string> GetAnon()
    {
        return "Authorized";
    }

    [Authorize(Roles = "User, Admin")]
    [HttpGet("GetUser")]
    public async Task<string> GetUser()
    {
        return "Authorized";
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("GetAdmin")]
    public async Task<string> GetAdmin()
    {
        return "Authorized";
    }

    public async Task<string> GetSecret(Login login, IConfiguration config)
    {
        var endPoint = config["VaultName"] ?? "<blank>";

        var httpClientHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
        };

        // Initialize one of the several auth methods.
        IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

        // Initialize settings. You can also set proxies, custom delegates, etc. here.
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

public class Response
{
    public string id { get; set; }
    public string loginResult { get; set; }
}
