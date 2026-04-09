using JwtAuthDemo.Data;
using JwtAuthDemo.Models;
using JwtAuthDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ITokenService _tokenService;

    public AuthController(AppDbContext db, ITokenService tokenService)
    {
        _db = db;
        _tokenService = tokenService;
    }

    // ─────────────────────────────────────────────────────────────
    // POST /api/auth/login
    // Validates credentials → issues access token + refresh token
    // ─────────────────────────────────────────────────────────────
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // Step 1: Find user by email
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Email == request.Email);

        // Step 2: Verify password using BCrypt (never store plain text passwords)
        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            return Unauthorized(new { message = "Invalid email or password" });

        // Step 3: Generate short-lived JWT access token (60 min)
        var accessToken = _tokenService.GenerateAccessToken(user);

        // Step 4: Generate long-lived refresh token and save to DB (30 days)
        var refreshToken = await CreateAndSaveRefreshTokenAsync(user.Id);

        // Step 5: Send refresh token in HttpOnly Cookie
        // HttpOnly = JS cannot read it (XSS safe)
        // Secure = HTTPS only
        // SameSite = CSRF protection
        SetRefreshTokenCookie(refreshToken);

        // Step 6: Return access token in response body
        // Client stores this in memory and uses in Authorization header
        return Ok(new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenExpiry = DateTime.UtcNow.AddMinutes(60)
        });
    }

    // ─────────────────────────────────────────────────────────────
    // POST /api/auth/refresh
    // Called when access token expires → issues new tokens
    // ─────────────────────────────────────────────────────────────
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        // Step 1: Read refresh token from HttpOnly Cookie
        var incomingToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(incomingToken))
            return Unauthorized(new { message = "No refresh token found" });

        // Step 2: Find token in DB with user details
        var storedToken = await _db.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.Token == incomingToken);

        if (storedToken == null)
            return Unauthorized(new { message = "Invalid refresh token" });

        // Step 3: Check for token reuse (security - rotation detection)
        if (storedToken.IsRevoked)
        {
            // Someone is reusing an already-used token — possible token theft!
            // Revoke ALL tokens for this user to force re-login
            await RevokeAllUserTokensAsync(storedToken.UserId);
            return Unauthorized(new { message = "Token reuse detected. All sessions revoked." });
        }

        // Step 4: Check expiry
        if (storedToken.ExpiresAt < DateTime.UtcNow)
            return Unauthorized(new { message = "Refresh token expired. Please login again." });

        // Step 5: Rotate — revoke old token, create new one
        storedToken.IsRevoked = true;
        var newRefreshToken = await CreateAndSaveRefreshTokenAsync(storedToken.UserId);
        storedToken.ReplacedByToken = newRefreshToken; // track rotation chain
        await _db.SaveChangesAsync();

        // Step 6: Generate new access token
        var newAccessToken = _tokenService.GenerateAccessToken(storedToken.User);

        // Step 7: Send new refresh token cookie and return new access token
        SetRefreshTokenCookie(newRefreshToken);

        return Ok(new TokenResponse
        {
            AccessToken = newAccessToken,
            AccessTokenExpiry = DateTime.UtcNow.AddMinutes(60)
        });
    }

    // ─────────────────────────────────────────────────────────────
    // POST /api/auth/logout
    // Revokes refresh token and clears cookie
    // ─────────────────────────────────────────────────────────────
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var token = Request.Cookies["refreshToken"];

        if (!string.IsNullOrEmpty(token))
        {
            // Revoke refresh token in DB
            var storedToken = await _db.RefreshTokens
                .FirstOrDefaultAsync(r => r.Token == token);

            if (storedToken != null && !storedToken.IsRevoked)
            {
                storedToken.IsRevoked = true;
                await _db.SaveChangesAsync();
            }
        }

        // Delete cookie from browser
        // Note: Access token is still valid until its expiry (60 min)
        // This is the stateless trade-off of JWT — acceptable for most apps
        Response.Cookies.Delete("refreshToken");

        return Ok(new { message = "Logged out successfully" });
    }

    // ─────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────

    private async Task<string> CreateAndSaveRefreshTokenAsync(int userId)
    {
        var token = _tokenService.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            Token = token,
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            IsRevoked = false,
            CreatedAt = DateTime.UtcNow
        };

        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();

        return token;
    }

    private void SetRefreshTokenCookie(string token)
    {
        Response.Cookies.Append("refreshToken", token, new CookieOptions
        {
            HttpOnly = true,                     // JavaScript cannot read this cookie
            Secure = true,                       // Sent only over HTTPS
            SameSite = SameSiteMode.Strict,      // Not sent on cross-site requests (CSRF protection)
            Expires = DateTime.UtcNow.AddDays(30)
        });
    }

    private async Task RevokeAllUserTokensAsync(int userId)
    {
        var tokens = await _db.RefreshTokens
            .Where(r => r.UserId == userId && !r.IsRevoked)
            .ToListAsync();

        foreach (var token in tokens)
            token.IsRevoked = true;

        await _db.SaveChangesAsync();
    }
}
