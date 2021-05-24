using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication_K.Jwt
{
    public interface IJwtAuthenticationManager
    {
        List<UserModel> GetAllUsers();
        AuthenticationResponse Authenticate(UserModel userModel);
        AuthenticationResponse RefreshToken(RefreshCred refreshCred);
    }
}
