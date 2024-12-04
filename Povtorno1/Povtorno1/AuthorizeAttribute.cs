// AuthenticationService.cs
using System;

namespace OnlinePropertyBookingPlatform.Controllers
{
    internal class AuthorizeAttribute : Attribute
    {
        public string Roles { get; set; }
    }
}