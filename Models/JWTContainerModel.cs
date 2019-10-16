using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace SalesForceJWT.Models
{
    public class JWTContainerModel : IAuthContainerModel
    {
        public string SecretKey { get; set; } = "D00DF981EC3E8BB2B30216F86B73CF2A632650A6A0541577D9FCE4D096581332"; // needs to be added to environment variable rather than hard coded
        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;
        public int ExpireMinutes { get; set; } = 10080; // 7 days
        public Claim[] Claims { get; set; }
    }
}
