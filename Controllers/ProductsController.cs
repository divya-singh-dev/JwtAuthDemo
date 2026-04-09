using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthDemo.Controllers;

/// <summary>
/// Demonstrates Role-based, Claims-based, and Policy-based authorization
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize] // All endpoints require a valid JWT by default
public class ProductsController : ControllerBase
{
    // ─────────────────────────────────────────────────────────────
    // GET /api/products
    // Any logged-in user can access
    // Shows how to read claims from JWT inside a controller
    // ─────────────────────────────────────────────────────────────
    [HttpGet]
    public IActionResult GetAll()
    {
        // Reading claims from JWT — these were set in TokenService
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var department = User.FindFirst("department")?.Value;

        return Ok(new
        {
            message = "Products list - accessible by all logged-in users",
            loggedInUser = new { userId, email, role, department }
        });
    }

    // ─────────────────────────────────────────────────────────────
    // GET /api/products/{id}
    // Any logged-in user
    // ─────────────────────────────────────────────────────────────
    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        return Ok(new { message = $"Product {id} details" });
    }

    // ─────────────────────────────────────────────────────────────
    // POST /api/products
    // Only Admin or Manager role — ROLE-BASED authorization
    // ─────────────────────────────────────────────────────────────
    [HttpPost]
    [Authorize(Roles = "Admin,Manager")] // comma = OR condition
    public IActionResult Create([FromBody] object product)
    {
        return Ok(new { message = "Product created — you are Admin or Manager" });
    }

    // ─────────────────────────────────────────────────────────────
    // DELETE /api/products/{id}
    // Only Admin role — ROLE-BASED authorization
    // ─────────────────────────────────────────────────────────────
    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    public IActionResult Delete(int id)
    {
        return Ok(new { message = $"Product {id} deleted — you are Admin" });
    }

    // ─────────────────────────────────────────────────────────────
    // GET /api/products/export
    // Only Finance department — POLICY-BASED authorization
    // Policy defined in Program.cs: RequireClaim("department", "Finance")
    // ─────────────────────────────────────────────────────────────
    [HttpGet("export")]
    [Authorize(Policy = "FinanceOnly")]
    public IActionResult Export()
    {
        return Ok(new { message = "Export data — you are in Finance department" });
    }

    // ─────────────────────────────────────────────────────────────
    // GET /api/products/reports
    // Admin or Manager role — POLICY-BASED authorization
    // Policy defined in Program.cs: RequireRole("Admin", "Manager")
    // ─────────────────────────────────────────────────────────────
    [HttpGet("reports")]
    [Authorize(Policy = "AdminOrManager")]
    public IActionResult Reports()
    {
        return Ok(new { message = "Reports — you are Admin or Manager" });
    }

    // ─────────────────────────────────────────────────────────────
    // GET /api/products/public
    // No auth required — anonymous access
    // ─────────────────────────────────────────────────────────────
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult PublicEndpoint()
    {
        return Ok(new { message = "Public endpoint — no login required" });
    }
}
