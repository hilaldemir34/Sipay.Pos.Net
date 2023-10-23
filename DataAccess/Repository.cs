using Core.Utilities.Security.Hashing;
using Entities.Concrete;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataAccess
{
    public class Repository
    {
        public List<User> Users
        {
            get { return _users; }
        }

        public static List<User> _users = new List<User>
    {
        new User
        {
            App_Id = "app_id_1",
            App_SecretHash = Encoding.UTF8.GetBytes("base64_encoded_hash_1"),
            App_SecretSalt = Encoding.UTF8.GetBytes("salt_1")

        },


    };

     
    }
}