using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication_K.Jwt
{
    public class JwtAuthenticationManager : IJwtAuthenticationManager
    {
        private List<UserModel> userList = null;
        private readonly string SecretKey;
        private IDictionary<string, string> SavedTokens = new Dictionary<string, string>(); //Normally we will save this in database, for time being we are using In-Memory
        public JwtAuthenticationManager(string _secretKey)
        {
            SecretKey = _secretKey;
        }

        public List<UserModel> GetAllUsers()
        {
            userList = new List<UserModel>()
            {
                new UserModel(){UserName="Kanth",Password="1234",Role=UserRole.User},
                 new UserModel(){UserName="Basha",Password="1234",Role=UserRole.Admin}
            };

            return userList;
        }
        public AuthenticationResponse Authenticate(UserModel userModel)
        {
            AuthenticationResponse authenticationResponse = new AuthenticationResponse();

            authenticationResponse.JwtToken = GenerateJwtToken(userModel.UserName, DateTime.UtcNow, null); //Generate JWT from JWT Service
            authenticationResponse.RefreshToken = GenerateRefreshToken();   //Generates token from random number locally

            //Save the Refresh Token here(normally we will save this in database)
            SavedTokens.Add(userModel.UserName, authenticationResponse.RefreshToken);

            return authenticationResponse;
        }

        public AuthenticationResponse RefreshToken(RefreshCred refreshCred)
        {
            byte[] key = Encoding.ASCII.GetBytes(SecretKey);

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            SecurityToken securityToken = null;

            //Here we will validate the exist token
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };

            var principal = jwtSecurityTokenHandler.ValidateToken(refreshCred.JwtToken, tokenValidationParameters, out securityToken);

            var jwtToken = securityToken as JwtSecurityToken;

            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new Exception("Invalid Token Passed");
            }

            var userName = principal.Identity.Name;

            if (refreshCred.RefreshToken != SavedTokens[userName])
            {
                throw new Exception("Invalid Token Passed");
            }

            return AuthenticateWithRefreshToken(userName, principal.Claims.ToArray());
        }

        public AuthenticationResponse AuthenticateWithRefreshToken(string userName, Claim[] claims)
        {
            string jwtToken = GenerateJwtToken(userName, DateTime.UtcNow, claims);
            string refreshToken = GenerateRefreshToken();

            //Check the refresh token with refreshtoken we saved in database
            if (SavedTokens.ContainsKey(userName))
            {
                SavedTokens[userName] = refreshToken;
            }
            else
            {
                SavedTokens.Add(userName, refreshToken);
            }

            return new AuthenticationResponse
            {
                JwtToken = jwtToken,
                RefreshToken = refreshToken
            };
        }

        public string GenerateJwtToken(string userName, DateTime expires, Claim[] claims)
        {
            var user = userList.Where(m => m.UserName == userName).First();

            if (user == null)
                throw new Exception("Sorry!! User Not Found..");

            var key = Encoding.ASCII.GetBytes(SecretKey);

            var tokenHandler = new JwtSecurityTokenHandler();

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                    claims ?? new Claim[]
                    {
                        new Claim(ClaimTypes.Name, userName.ToString()),
                        new Claim(ClaimTypes.Role, user.Role.ToString())
                }),
                Expires = expires.AddMinutes(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            SecurityToken securityToken = tokenHandler.CreateToken(securityTokenDescriptor);    //Generates Token here
            string jwtToken = tokenHandler.WriteToken(securityToken);   //Converts Token into string

            return jwtToken;
        }

        public string GenerateRefreshToken()
        {
            string refreshToken = string.Empty;

            var randomNumber = new byte[32];

            using (var randomNumberGenerator = RandomNumberGenerator.Create())
            {
                randomNumberGenerator.GetBytes(randomNumber);
                refreshToken = Convert.ToBase64String(randomNumber);
            }

            return refreshToken;
        }
    }
}
