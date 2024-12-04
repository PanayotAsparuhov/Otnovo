// AuthenticationService.cs
using System;

namespace OnlinePropertyBookingPlatform.Controllers
{
    internal class RouteAttribute : Attribute
    {
        private string v;

        public RouteAttribute(string v)
        {
            this.v = v;
        }
    }
}