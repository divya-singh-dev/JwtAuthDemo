using JwtAuthDemo.Models;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthDemo.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Seed one Admin and one regular User for testing
        modelBuilder.Entity<User>().HasData(
            new User
            {
                Id = 1,
                Email = "admin@demo.com",
                // Password: Admin@123
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@123"),
                Role = "Admin",
                Department = "IT"
            },
            new User
            {
                Id = 2,
                Email = "finance@demo.com",
                // Password: Finance@123
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Finance@123"),
                Role = "User",
                Department = "Finance"
            }
        );
    }
}
