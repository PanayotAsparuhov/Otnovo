// AuthenticationService.cs
using System;

namespace OnlinePropertyBookingPlatform.Controllers
{
    internal class HttpGetAttribute : Attribute
    {
        private string v;

        public HttpGetAttribute(string v)
        {
            this.v = v;
        }
    }
}