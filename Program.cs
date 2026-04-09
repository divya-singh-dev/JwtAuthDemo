using System.Text;
using JwtAuthDemo.Data;
using JwtAuthDemo.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────
// 1. DATABASE — EF Core with SQL Server
// ─────────────────────────────────────────────────────────────
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default")));

// ─────────────────────────────────────────────────────────────
// 2. SERVICES
// ─────────────────────────────────────────────────────────────
builder.Services.AddScoped<ITokenService, TokenService>();

// ─────────────────────────────────────────────────────────────
// 3. AUTHENTICATION — JWT Bearer
// This middleware validates the JWT on every request
// ─────────────────────────────────────────────────────────────
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Validate who issued the token (must match Jwt:Issuer in appsettings)
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],

        // Validate who the token is for (must match Jwt:Audience in appsettings)
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],

        // Validate expiry — reject expired tokens
        ValidateLifetime = true,

        // Validate the signing key — ensures token was not tampered with
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]!)),

        // Allow small clock difference between servers (30 seconds)
        ClockSkew = TimeSpan.FromSeconds(30)
    };

    // Return clean 401 response on auth failure
    options.Events = new JwtBearerEvents
    {
        OnChallenge = context =>
        {
            context.HandleResponse();
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            return context.Response.WriteAsync(
                "{\"message\": \"Unauthorized. Please login or provide a valid token.\"}");
        },
        OnForbidden = context =>
        {
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            return context.Response.WriteAsync(
                "{\"message\": \"Forbidden. You do not have permission to access this resource.\"}");
        }
    };
});

// ─────────────────────────────────────────────────────────────
// 4. AUTHORIZATION POLICIES
// Define named rules once, reuse with [Authorize(Policy="Name")]
// ─────────────────────────────────────────────────────────────
builder.Services.AddAuthorization(options =>
{
    // Policy: user must have department claim = "Finance"
    options.AddPolicy("FinanceOnly", policy =>
        policy.RequireClaim("department", "Finance"));

    // Policy: user must be in Admin OR Manager role
    options.AddPolicy("AdminOrManager", policy =>
        policy.RequireRole("Admin", "Manager"));

    // Policy: user must be Admin AND in IT department (combining role + claim)
    options.AddPolicy("ITAdmin", policy =>
        policy.RequireRole("Admin")
              .RequireClaim("department", "IT"));
});

// ─────────────────────────────────────────────────────────────
// 5. CONTROLLERS + SWAGGER
// ─────────────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Swagger with JWT support — allows you to test protected endpoints
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "JWT Auth Demo API",
        Version = "v1",
        Description = "Demo project: JWT Authentication + Refresh Tokens + Role/Claims/Policy Authorization"
    });

    // Add JWT Bearer input to Swagger UI
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token below. Example: eyJhbGci..."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ─────────────────────────────────────────────────────────────
// 6. BUILD APP
// ─────────────────────────────────────────────────────────────
var app = builder.Build();

// ─────────────────────────────────────────────────────────────
// 7. MIDDLEWARE PIPELINE
// Order matters! Authentication must come before Authorization.
// ─────────────────────────────────────────────────────────────
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "JWT Auth Demo v1");
    c.RoutePrefix = string.Empty; // Swagger at root URL
});

app.UseHttpsRedirection();

app.UseAuthentication(); // Step 1: Who are you? (validates JWT, sets User identity)
app.UseAuthorization();  // Step 2: What can you do? (checks roles/claims/policies)

app.MapControllers();

// Auto-create DB and apply migrations on startup (for dev only)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

app.Run();
