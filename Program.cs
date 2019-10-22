using SalesForceJWT.Managers;
using System;

namespace SalesForceJWT
{
    class Program
    {
        static void Main(string[] args)
        {
            IAuthService authService = new JWTService();

            string jwt = authService.GenerateToken("Subscriptions@solutiondesign.com.full");
            string accessToken = authService.GetAccessToken(jwt);

            Console.WriteLine("Access Token:");
            Console.WriteLine(accessToken);
        }
    }
}
