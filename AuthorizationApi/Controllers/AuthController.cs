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

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;

   public AuthController(ILogger<AuthController> logger, IConfiguration config)
{
        _config = config;
        _logger = logger;
}
private string GenerateJwtToken(string email)
{
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, email)
    };

    var token = new JwtSecurityToken(
        issuer: _config["Issuer"],
        audience: "http://localhost",
        claims: claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}

[AllowAnonymous]
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] Login login)
{
    var secret = await GetSecret(login, _config);
    if (login.Password == secret.ToString())
    {
        var token = GenerateJwtToken(login.EmailAddress);
        return Ok(new { token });
    }
    return Unauthorized();
}

public async Task<string>GetSecret(Login login, IConfiguration config)
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

        return minkode?.ToString();
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error retrieving secret from Vault");
        return string.Empty;
    }
}
}
