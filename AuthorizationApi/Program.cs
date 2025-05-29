using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using NLog;

var builder = WebApplication.CreateBuilder(args);
// Setup gateway client (used to call backend APIs)
    var gatewayUrl = builder.Configuration["GatewayUrl"] ?? "http://localhost:5002/";
    builder.Services.AddHttpClient("gateway", client =>
    {
        client.BaseAddress = new Uri(gatewayUrl);
        client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
    });
    Console.WriteLine($"Gateway set to{gatewayUrl}");
string mySecret = Environment.GetEnvironmentVariable("Secret") ?? "none";
string myIssuer = Environment.GetEnvironmentVariable("Issuer") ?? "none";
builder.Services
.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
options.TokenValidationParameters = new TokenValidationParameters()
{
ValidateIssuer = true,
ValidateAudience = true,
ValidateLifetime = true,
ValidateIssuerSigningKey = true,
ValidIssuer = myIssuer,
ValidAudience = "http://localhost",
IssuerSigningKey =
new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
};
});
// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
