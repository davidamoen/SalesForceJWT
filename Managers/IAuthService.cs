using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace SalesForceJWT.Managers
{
    public interface IAuthService
    {
        string GenerateToken(string sub);
        string GetAccessToken(string jwt);
    }
}
