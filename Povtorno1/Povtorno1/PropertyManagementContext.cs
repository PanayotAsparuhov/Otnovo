// AuthenticationService.cs
using System;
using System.Threading.Tasks;

namespace OnlinePropertyBookingPlatform.Repositories
{
    public class PropertyManagementContext
    {
        public object Users { get; internal set; }

        internal Task SaveChangesAsync()
        {
            throw new NotImplementedException();
        }
    }
}