using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthorizationApi.Model;
namespace AuthorizationApi.Controllers;

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
    if (login.EmailAddress == "haavy_user" && login.Password == "aaakodeord")
    {
        var token = GenerateJwtToken(login.EmailAddress);
        return Ok(new { token });
    }

    return Unauthorized();
}



}
