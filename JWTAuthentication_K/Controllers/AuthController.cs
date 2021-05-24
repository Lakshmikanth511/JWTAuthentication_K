using JWTAuthentication_K.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication_K.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IJwtAuthenticationManager jwtAuthenticationManager = null;

        public AuthController(IJwtAuthenticationManager _jwtAuthenticationManager)
        {
            jwtAuthenticationManager = _jwtAuthenticationManager;
        }

        /// <summary>
        /// Sample Test API
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetM")]
        public IActionResult Get()
        {
            return Ok("Hello");
        }

        /// <summary>
        /// API for User Logging
        /// </summary>
        /// <param name="userModel"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Login")]
        public IActionResult Login(UserModel userModel)
        {
            if (string.IsNullOrEmpty(userModel.UserName) && string.IsNullOrEmpty(userModel.Password))
                return BadRequest("Invalid Credentials!!");

            var userList = jwtAuthenticationManager.GetAllUsers();

            UserModel user = userList.Where(a => a.UserName == userModel.UserName && a.Password == userModel.Password).First();

            if (user == null)
                return Unauthorized();

            var tokenAuthenticationResponse = jwtAuthenticationManager.Authenticate(userModel);

            return Ok(tokenAuthenticationResponse);
        }

        /// <summary>
        /// API to Refresh the token
        /// </summary>
        /// <param name="refreshCred"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("RefreshToken")]
        public IActionResult RefreshToken(RefreshCred refreshCred)
        {
            if (string.IsNullOrEmpty(refreshCred.JwtToken) && string.IsNullOrEmpty(refreshCred.RefreshToken))
                return BadRequest("Token(s) invalid!!");

            var refreshTokenAuthenticationResponse = jwtAuthenticationManager.RefreshToken(refreshCred);

            return Ok(refreshTokenAuthenticationResponse);
        }
    }
}
