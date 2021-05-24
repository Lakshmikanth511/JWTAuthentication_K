using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication_K
{
    public class AuthenticationResponse
    {
        public string JwtToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class RefreshCred
    {
        public string JwtToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
