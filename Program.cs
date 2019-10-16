using SalesForceJWT.Managers;
using SalesForceJWT.Models;
using System;
using System.Security.Claims;

namespace SalesForceJWT
{
    class Program
    {
        static void Main(string[] args)
        {
            IAuthContainerModel model = GetJWTContainerModel("Dave Moen", "david.moen@solutiondesign.com");
            IAuthService authService = new JWTService(model.SecretKey);

            string token = authService.GenerateToken(model);
        }

        private static JWTContainerModel GetJWTContainerModel(string name, string email)
        {
            return new JWTContainerModel
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, name),
                    new Claim(ClaimTypes.Email, email)
                }
            };
        }
    }
}
