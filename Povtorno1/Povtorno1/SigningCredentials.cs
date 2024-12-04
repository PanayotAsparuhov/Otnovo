// AuthenticationService.cs
namespace OnlinePropertyBookingPlatform.Services
{
    internal class SigningCredentials
    {
        private SymmetricSecurityKey symmetricSecurityKey;
        private object hmacSha256Signature;

        public SigningCredentials(SymmetricSecurityKey symmetricSecurityKey, object hmacSha256Signature)
        {
            this.symmetricSecurityKey = symmetricSecurityKey;
            this.hmacSha256Signature = hmacSha256Signature;
        }
    }
}