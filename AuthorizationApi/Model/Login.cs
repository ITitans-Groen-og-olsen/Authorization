using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace AuthorizationApi.Model;

public class Login
{
    public string? EmailAddress { get; set; }
    public string? Password { get; set; }
}