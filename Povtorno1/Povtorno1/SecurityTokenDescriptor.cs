// AuthenticationService.cs
using System;
using System.Security.Claims;

namespace OnlinePropertyBookingPlatform.Services
{
    internal class SecurityTokenDescriptor
    {
        public ClaimsIdentity Subject { get; set; }
        public DateTime Expires { get; set; }
        public object SigningCredentials { get; set; }
    }
}