// AuthenticationService.cs
using System;

namespace OnlinePropertyBookingPlatform.Controllers
{
    internal class HttpPostAttribute : Attribute
    {
        private string v;

        public HttpPostAttribute(string v)
        {
            this.v = v;
        }
    }
}