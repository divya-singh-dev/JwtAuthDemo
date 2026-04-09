using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuthDemo.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthDemo.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _config;

    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    /// <summary>
    /// Generates a signed JWT access token.
    /// Contains: userId, email, role, department, jti (unique token ID), iat (issued at)
    /// Expires in 60 minutes.
    /// Algorithm: HMAC SHA256 (symmetric - one shared secret key)
    /// </summary>
    public string GenerateAccessToken(User user)
    {
        // --- CLAIMS (payload) ---
        // These are the key-value pairs stored inside the JWT
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),  // subject = userId
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),                       // used by [Authorize(Roles="Admin")]
            new Claim("department", user.Department),                    // custom claim for policy-based auth
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // unique ID per token (for revocation)
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

        // --- SIGNING KEY ---
        // HS256 = HMAC SHA256 (symmetric)
        // Same key used to sign AND verify — keep it secret in Key Vault in production
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]!));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // --- BUILD TOKEN ---
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],          // who issued the token
            audience: _config["Jwt:Audience"],       // who should accept the token
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(60), // SHORT expiry — 60 minutes
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Generates a secure random string to be used as refresh token.
    /// This is NOT a JWT — it has no claims, no expiry baked in.
    /// Expiry and revocation are controlled by the database.
    /// Stored in DB and sent to client via HttpOnly Cookie.
    /// </summary>
    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
}
