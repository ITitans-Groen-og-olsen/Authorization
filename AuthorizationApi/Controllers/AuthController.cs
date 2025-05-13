using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
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
    private string GenerateJwtToken(){
        return "";
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login(){
        return null;
    }
}
