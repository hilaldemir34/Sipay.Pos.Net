using Business.Abstract;
using DataAccess;
using Entities.Concrete;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Business.Concrete
{
    public class UserManager : IUserService
    {
        public List<User> users;

        public UserManager()
        {
            users=new List<User> { new User(){
            App_Id="hilal",
            App_SecretHash=Encoding.UTF8.GetBytes("hash"),
            App_SecretSalt=Encoding.UTF8.GetBytes("salt")
            } };
        }
        public void Add(User user)
        {
            users.Add(user);
        }

        public User GetById(string app_id)
        {
            return users.FirstOrDefault(x => x.App_Id == app_id);
        }

        public List<OperationClaim> GetClaims(User user)
        {
            User foundUser = GetById(user.App_Id);
            if (foundUser != null)
            {
                return foundUser.Claims;
            }
            else
            {
                // Kullanıcı bulunamadıysa uygun bir hata işlemini gerçekleştirin veya boş bir liste döndürün.
                return new List<OperationClaim>();
            }
        }
    }
}

