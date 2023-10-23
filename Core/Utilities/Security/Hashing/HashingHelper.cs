using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Utilities.Security.Hashing
{
    public class HashingHelper
    {
        public static void CreatePasswordHash(string app_secret, out byte[] app_secretHash, out byte[] app_secretSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                app_secretSalt = hmac.Key;
                app_secretHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(app_secret));
            }
        }

        public static bool VerifyPasswordHash(string app_secret, byte[] app_secretHash, byte[] app_secretSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(app_secretSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(app_secret));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != app_secretHash[i])
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }
}
