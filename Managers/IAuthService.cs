using SalesForceJWT.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace SalesForceJWT.Managers
{
    public interface IAuthService
    {
        string SecretKey { get; set; }
        bool IsTokenValid(string token);
        string GenerateToken(IAuthContainerModel model);
        IEnumerable<Claim> GetTokenClaims(string token);
    }
}
