using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication_K.Controllers
{
    [Authorize("ApiUser")]
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [HttpGet]
        [Route("Test1")]
        [Authorize(Roles = "User")]
        public ActionResult<string> Test1()
        {
            return "Hello Test1";
        }

        [HttpGet]
        [Route("Test2")]
        [Authorize(Roles = "Admin")]
        public ActionResult<string> Test2()
        {
            return "Hello Test2";
        }

        [HttpGet]
        [Route("Test3")]
        [Authorize(Roles = "Admin,User")]
        public ActionResult<string> Test3()
        {
            return "Hello Test3";
        }
    }
}
