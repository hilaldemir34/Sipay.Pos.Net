using Core.Utilities.Results;
using Core.Utilities.Security.Jwt;
using Entities.Concrete;
using Entities.Dto;

namespace Business.Abstract
{
    public interface IAuthService
    {

        IDataResult<User> Login(UserForLoginDto userForLoginDto);
        IDataResult<AccessToken> CreateAccessToken(User user);
        IDataResult<User> Register(UserForRegisterDto userForRegisterDto, string app_secret);
        IResult UserExists(string app_id);
    }
}