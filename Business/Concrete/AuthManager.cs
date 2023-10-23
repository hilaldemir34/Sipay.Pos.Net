using Business.Abstract;
using Core.Utilities.Results;
using Core.Utilities.Security.Hashing;
using Core.Utilities.Security.Jwt;
using Entities.Concrete;
using Entities.Dto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Business.Concrete
{
    public class AuthManager : IAuthService
    {
        private IUserService _userService;
        private ITokenHelper _tokenHelper;

        public AuthManager(IUserService userService, ITokenHelper tokenHelper)
        {
            _userService = userService;
            _tokenHelper = tokenHelper;
        }
        public IResult UserExists(string app_id)
        {
            if (_userService.GetById(app_id) != null)
            {
                return new ErrorResult();
            }
            return new SuccessResult();
        }
        public IDataResult<AccessToken> CreateAccessToken(User user)
        {
            var claims = _userService.GetClaims(user);
            var accessToken = _tokenHelper.CreateToken(user, claims);
            return new SuccessDataResult<AccessToken>(accessToken, "Token created");
        }
        public IDataResult<User> Register(UserForRegisterDto userForRegisterDto, string app_secret)
        {
            byte[] app_secretHash, app_secretSalt;
            HashingHelper.CreatePasswordHash(app_secret, out app_secretHash, out app_secretSalt);
            var user = new User
            {
                App_Id = userForRegisterDto.App_id,
                App_SecretHash = app_secretHash,
                App_SecretSalt = app_secretSalt

            };
            _userService.Add(user);
            return new SuccessDataResult<User>(user);
        }
        public IDataResult<User> Login(UserForLoginDto userForLoginDto)
        {
            var userToCheck = _userService.GetById(userForLoginDto.App_id);
            if (userToCheck == null)
            {
                return new ErrorDataResult<User>("User not found");
            }

            if (!HashingHelper.VerifyPasswordHash(userForLoginDto.App_secret, userToCheck.App_SecretHash, userToCheck.App_SecretSalt))
            {
                return new ErrorDataResult<User>("App_secret not found");
            }

            return new SuccessDataResult<User>(userToCheck, "Successfull");
        }



    }
}
