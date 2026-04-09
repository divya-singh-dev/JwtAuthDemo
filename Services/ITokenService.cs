using JwtAuthDemo.Models;

namespace JwtAuthDemo.Services;

public interface ITokenService
{
    /// <summary>
    /// Generates a short-lived JWT access token containing user claims
    /// </summary>
    string GenerateAccessToken(User user);

    /// <summary>
    /// Generates a long-lived secure random refresh token (NOT a JWT)
    /// </summary>
    string GenerateRefreshToken();
}
