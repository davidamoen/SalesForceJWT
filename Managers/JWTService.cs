using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SalesForceJWT.Models;

namespace SalesForceJWT.Managers
{
    public class JWTService : IAuthService
    {
        public JWTService(string secretKey)
        {
            this.SecretKey = secretKey;
        }

        public string SecretKey { get; set; }

        public string GenerateToken(IAuthContainerModel model)
        {
            if (model == null || model.Claims == null || model.Claims.Length == 0)
            {
                throw new ArgumentException("Arguments to create token are not valid");
            }

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(model.Claims),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToInt32(model.ExpireMinutes)),
                SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), model.SecurityAlgorithm)
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = tokenHandler.CreateToken(tokenDescriptor);
            string token = tokenHandler.WriteToken(securityToken);
            return token;
        }

        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException("Token is null or empty");
            }

            TokenValidationParameters validationParameters = GetTokenValidationParameters();
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                return tokenValid.Claims;
            }
            catch(Exception ex)
            {
                throw ex;
            }
        }

        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException("Token is null or empty");
            }

            TokenValidationParameters validationParams = GetTokenValidationParameters();

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = tokenHandler.ValidateToken(token, validationParams, out SecurityToken validatedToken);
                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        private SecurityKey GetSymmetricSecurityKey()
        {
            byte[] symmetricKey = Convert.FromBase64String(SecretKey);
            return new SymmetricSecurityKey(symmetricKey);
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = GetSymmetricSecurityKey()
            };
        }
    }
}
