// AuthenticationService.cs
namespace OnlinePropertyBookingPlatform.Services
{
    internal class SymmetricSecurityKey
    {
        private object key;

        public SymmetricSecurityKey(object key)
        {
            this.key = key;
        }
    }
}