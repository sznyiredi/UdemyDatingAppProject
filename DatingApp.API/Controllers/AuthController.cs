using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;

        }

        [HttpPost("register")]

        public async Task<IActionResult> Register(UserforRegisterDto userforRegisterDto)
        {
            // Validate request
            userforRegisterDto.Username = userforRegisterDto.Username.ToLower();

            if (await _repo.UserExist(userforRegisterDto.Username))
                return BadRequest("Username already exists");

            var userToCreate = new User
            {
                Username = userforRegisterDto.Username
            };

            var createdUser = _repo.Register(userToCreate, userforRegisterDto.Password);
            return StatusCode(201);
        }
        [HttpPost("login")]

        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            //search for user account
            var userFromRepo = _repo.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password);
            
            //if not found, return unauthorized
            if (userFromRepo == null)
               return Unauthorized();
            //start building a claim. it contains two claims(id and username)
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)              
            };
            //we have to sing the token to know if it is a valid key if it comes back
            //generate key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value)); //comes from appsettings.json file
            //encrypting the key with a hashing algoritm
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //create the token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //adding our claims(id and username)
                Subject = new ClaimsIdentity(claims),
                //expiration date
                Expires = DateTime.Now.AddDays(1),
                //adding the signing credentials
                SigningCredentials = creds
            };

            //add token Handler
            var tokenHandler = new JwtSecurityTokenHandler();
            
            //token handler alows us to create the token
            var token = tokenHandler.CreateToken(tokenDescriptor);

            //write the token into the response and send back to the client
            return Ok(new{
                token = tokenHandler.WriteToken(token)
            });
            
        }
    }

}