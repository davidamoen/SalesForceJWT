using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SalesForceJWT.Managers
{
    public class JWTService : IAuthService
    {
        private const string audience = "https://test.salesforce.com";
        private const string client_id = "3MVG9FG3dvS828gLkC4zNXhqw8.tbg5mTTyAG3YfgnnW.3LnsKl.WNIxxy.3tvcL68XchWElJEKoiROLnBoSK";
        private const string key_file = "C:\\users\\micha\\desktop\\salesforce.key";

        public string GenerateToken(string sub)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = audience,
                Issuer = client_id,
                Subject = new ClaimsIdentity(new[] { new Claim(JwtRegisteredClaimNames.Sub, sub) }),
                Expires = DateTime.UtcNow.AddMinutes(3),
                SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), SecurityAlgorithms.RsaSha256)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(securityToken);

            return token;
        }

        public string GetAccessToken(string jwt)
        {
            using (var client = new HttpClient())
            {
                var content = new FormUrlEncodedContent(new Dictionary<string, string>()
                {
                    { "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                    { "assertion", jwt }
                });

                var response = client.PostAsync($"{audience}/services/oauth2/token", content)
                    .GetAwaiter().GetResult();
                if (response.IsSuccessStatusCode)
                {
                    var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var obj = JsonSerializer.Deserialize<TokenResponse>(json);
                    return obj.access_token as string;
                }
            }

            return null;
        }

        private SecurityKey GetSymmetricSecurityKey()
        {
            var key = File.ReadAllText(key_file);
            var rsa = GetRsaParameters(key);
            return new RsaSecurityKey(rsa);
        }

        private static RSAParameters GetRsaParameters(string rsaPrivateKey)
        {
            var byteArray = Encoding.ASCII.GetBytes(rsaPrivateKey);
            using (var ms = new MemoryStream(byteArray))
            {
                using (var sr = new StreamReader(ms))
                {
                    // use Bouncy Castle to convert the private key to RSA parameters
                    var pemReader = new PemReader(sr);
                    return DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)pemReader.ReadObject());
                }
            }
        }

        private class TokenResponse
        {
            public string access_token { get; set; }
        }
    }
}
