using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Service.Authorization.Client.Models;
using Service.Core.Client.Services;
using Service.Grpc;
using Service.UserInfo.Crud.Grpc;
using Service.UserInfo.Crud.Grpc.Models;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;
using SecurityToken = Microsoft.IdentityModel.Tokens.SecurityToken;
using SymmetricSecurityKey = Microsoft.IdentityModel.Tokens.SymmetricSecurityKey;

namespace Service.Authorization.Client.Services
{
	public class TokenService : ITokenService
	{
		private readonly IGrpcServiceProxy<IUserInfoService> _userInfoService;
		private readonly IEncoderDecoder _encoderDecoder;
		private readonly ILogger<TokenService> _logger;
		private readonly ISystemClock _systemClock;

		private readonly string _jwtAudience;
		private readonly string _jwtSecret;
		private readonly int _jwtTokenExpireMinutes;
		private readonly int _refreshTokenExpireMinutes;

		public TokenService(IGrpcServiceProxy<IUserInfoService> userInfoService, 
			IEncoderDecoder encoderDecoder,
			ILogger<TokenService> logger,
			ISystemClock systemClock,
			string jwtAudience, string jwtSecret, int jwtTokenExpireMinutes, int refreshTokenExpireMinutes)
		{
			_userInfoService = userInfoService;
			_encoderDecoder = encoderDecoder;
			_jwtAudience = jwtAudience;
			_jwtSecret = jwtSecret;
			_jwtTokenExpireMinutes = jwtTokenExpireMinutes;
			_refreshTokenExpireMinutes = refreshTokenExpireMinutes;
			_logger = logger;
			_systemClock = systemClock;
		}

		public async ValueTask<TokenInfo> GenerateTokensAsync(string userName, string ipAddress, string password = null)
		{
			UserInfoResponse userInfo = await _userInfoService.Service.GetUserInfoByLoginAsync(new UserInfoAuthRequest {UserName = userName, Password = password});

			return await GetNewTokenInfo(userInfo, ipAddress);
		}

		public async ValueTask<TokenInfo> RefreshTokensAsync(string currentRefreshToken, string ipAddress)
		{
			RefreshTokenInfo tokenInfo = DecodeReshreshToken(currentRefreshToken);

			if (tokenInfo == null)
				return await ValueTask.FromResult<TokenInfo>(null);

			if (tokenInfo.RefreshTokenExpires < _systemClock.Now)
			{
				_logger.LogWarning("Token {currentRefreshToken} for user: {userId} has expired ({date})", currentRefreshToken, tokenInfo.RefreshTokenUserId, tokenInfo.RefreshTokenExpires);
				return await ValueTask.FromResult<TokenInfo>(null);
			}

			if (tokenInfo.RefreshTokenIpAddress != ipAddress)
			{
				_logger.LogWarning("Token {currentRefreshToken} for user: {userId} has changed ip (was: {ip1}, now: {ip2})", currentRefreshToken, tokenInfo.RefreshTokenUserId, tokenInfo.RefreshTokenIpAddress, ipAddress);
				return await ValueTask.FromResult<TokenInfo>(null);
			}

			UserInfoResponse userInfo = await _userInfoService.Service.GetUserInfoByIdAsync(new UserInfoRequest { UserId = tokenInfo.RefreshTokenUserId});

			return await GetNewTokenInfo(userInfo, ipAddress);
		}

		private async ValueTask<TokenInfo> GetNewTokenInfo(UserInfoResponse userInfoResponse, string ipAddress)
		{
			UserInfoGrpcModel userInfo = userInfoResponse?.UserInfo;
			if (userInfo == null)
				return await ValueTask.FromResult<TokenInfo>(null);

			_logger.LogDebug("Generate new token info for user: {user}, ip: {ip}", userInfo.UserId, ipAddress);

			return new TokenInfo
			{
				Token = GenerateJwtToken(userInfo),
				RefreshToken = GenerateRefreshToken(userInfo, ipAddress)
			};
		}

		private string GenerateJwtToken(UserInfoGrpcModel userInfo)
		{
			byte[] key = Encoding.ASCII.GetBytes(_jwtSecret);
			var clientId = userInfo.UserId.ToString();

			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.Aud, _jwtAudience),
				new Claim(ClaimsIdentity.DefaultNameClaimType, clientId),
				new Claim(ClaimsIdentity.DefaultRoleClaimType, userInfo.Role)
			};

			var tokenHandler = new JwtSecurityTokenHandler();
			
			var identity = new GenericIdentity(clientId);

			SecurityToken token = tokenHandler.CreateToken(new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(identity, claims),
				Expires = _systemClock.Now.AddMinutes(_jwtTokenExpireMinutes),
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
			});

			return tokenHandler.WriteToken(token);
		}

		private string GenerateRefreshToken(UserInfoGrpcModel userInfo, string ipAddress) => _encoderDecoder.EncodeProto(new RefreshTokenInfo
		{
			RefreshTokenUserId = userInfo.UserId,
			RefreshTokenIpAddress = ipAddress,
			RefreshTokenExpires = _systemClock.Now.AddMinutes(_refreshTokenExpireMinutes)
		});

		private RefreshTokenInfo DecodeReshreshToken(string token)
		{
			RefreshTokenInfo tokenInfo = null;

			try
			{
				tokenInfo = _encoderDecoder.DecodeProto<RefreshTokenInfo>(token);
			}
			catch (Exception exception)
			{
				_logger.LogError("Can't decode refresh token info ({token}), with message {message}", token, exception.Message);
			}

			return tokenInfo;
		}
	}
}