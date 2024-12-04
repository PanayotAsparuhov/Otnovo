// AuthenticationService.cs
using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using OnlinePropertyBookingPlatform.Models;
using OnlinePropertyBookingPlatform.Repositories;
using System.Net.Mail;
using OnlinePropertyBookingPlatform.Services;


namespace OnlinePropertyBookingPlatform.Services
{
    public class AuthenticationService
    {
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _configuration;
        private object user;

        public AuthenticationService(IUserRepository userRepository, IConfiguration configuration)
        {
            _userRepository = userRepository;
            _configuration = configuration;
        }

        public object BCrypt { get; private set; }

        public IConfiguration Get_configuration()
        {
            return _configuration;
        }

        public Task<string> AuthenticateAsync(string email, string password)
        {
            return AuthenticateAsync(email, password, _configuration);
        }

        public Task<string> AuthenticateAsync(string email, string password, IConfiguration _configuration)
        {
            return AuthenticateAsync(email, password, _configuration, user);
        }

        public async Task<string> AuthenticateAsync(string email, string password, IConfiguration _configuration, object user)
        {
            if (await _userRepository.FindByEmailAsync(email) != null && BCrypt.Net.BCrypt.Verify(password, (await _userRepository.FindByEmailAsync(email)).Password))
            {
                // Generate JWT Token
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
            new Claim(ClaimTypes.Name, (await _userRepository.FindByEmailAsync(email)).Id.ToString()),
            new Claim(ClaimTypes.Role, (await _userRepository.FindByEmailAsync(email)).Role)
        }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:Key"])), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }

            return null;
        }


        public async Task<bool> RegisterUserAsync(RegisterRequest request)
        {
            // Check if user already exists
            var existingUser = await _userRepository.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return false;
            }

            // Hash the password
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);

            // Create new user
            var newUser = new User
            {
                Email = request.Email,
                Password = hashedPassword,
                Role = request.Role
            };

            await _userRepository.AddAsync(newUser);
            return true;
        }

        public async Task<bool> SendPasswordResetLinkAsync(string email)
        {
            var user = await _userRepository.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            // Generate reset token (for simplicity, just a GUID here)
            var resetToken = Guid.NewGuid().ToString();

            // TODO: Store reset token in the database linked to the user

            // Send reset link via email
            var resetLink = $"https://your-app.com/reset-password?token={resetToken}";
            var mailMessage = new MailMessage("noreply@your-app.com", email)
            {
                Subject = "Password Reset Request",
                Body = $"Please reset your password using the following link: {resetLink}",
                IsBodyHtml = true
            };

            using (var smtpClient = new SmtpClient("smtp.your-email-provider.com"))
            {
                smtpClient.Port = 587;
                smtpClient.Credentials = new System.Net.NetworkCredential("your-email", "your-password");
                smtpClient.EnableSsl = true;
                await smtpClient.SendMailAsync(mailMessage);
            }

            return true;
        }
    }
}



namespace OnlinePropertyBookingPlatform.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly AuthenticationService _authService;

        public UserController(AuthenticationService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var token = await _authService.AuthenticateAsync(request.Email, request.Password, _authService.Get_configuration());
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized("Invalid credentials");
            }

            return Ok(new { Token = token });
        }

        private IActionResult Ok(object value)
        {
            throw new NotImplementedException();
        }

        private IActionResult Unauthorized(string v)
        {
            throw new NotImplementedException();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var success = await _authService.RegisterUserAsync(request);
            if (!success)
            {
                return BadRequest("User already exists");
            }

            return Ok("User registered successfully");
        }

        private IActionResult BadRequest(string v)
        {
            throw new NotImplementedException();
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] PasswordResetRequest request)
        {
            var success = await _authService.SendPasswordResetLinkAsync(request.Email);
            if (!success)
            {
                return BadRequest("User not found");
            }

            return Ok("Password reset link sent");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnly()
        {
            return Ok("Admin endpoint accessed successfully");
        }

        [Authorize(Roles = "EstateOwner")]
        [HttpGet("owner-only")]
        public IActionResult OwnerOnly()
        {
            return Ok("Estate Owner endpoint accessed successfully");
        }

        [Authorize(Roles = "Customer")]
        [HttpGet("customer-only")]
        public IActionResult CustomerOnly()
        {
            return Ok("Customer endpoint accessed successfully");
        }
    }
}

namespace OnlinePropertyBookingPlatform.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly PropertyManagementContext _context;

        public UserRepository(PropertyManagementContext context)
        {
            _context = context;
        }

        public async Task<User> FindByEmailAsync(string email)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task AddAsync(User user)
        {
            object value = await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();
        }
    }

    public interface IUserRepository
    {
        Task<User> FindByEmailAsync(string email);
        Task AddAsync(User user);
    }
}

// Models/User.cs
namespace OnlinePropertyBookingPlatform.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}

// Models/LoginRequest.cs
namespace OnlinePropertyBookingPlatform.Models
{
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}

// Models/RegisterRequest.cs
namespace OnlinePropertyBookingPlatform.Models
{
    public class RegisterRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}

// Models/PasswordResetRequest.cs
namespace OnlinePropertyBookingPlatform.Models
{
    public class PasswordResetRequest
    {
        public string Email { get; set; }
    }
}
