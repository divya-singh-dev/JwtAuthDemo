namespace JwtAuthDemo.Models;

// Returned to client after login or refresh
// NOTE: Refresh token is NOT here — it goes in HttpOnly Cookie only
public class TokenResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public DateTime AccessTokenExpiry { get; set; }
    public string TokenType { get; set; } = "Bearer";
}
