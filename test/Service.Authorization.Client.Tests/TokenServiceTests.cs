using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Service.Authorization.Client.Models;
using Service.Authorization.Client.Services;
using Service.Core.Client.Constants;
using Service.Core.Client.Services;
using Service.Grpc;
using Service.UserInfo.Crud.Grpc;
using Service.UserInfo.Crud.Grpc.Models;

namespace Service.Authorization.Client.Tests
{
	public class TokenServiceTests
	{
		private readonly Guid _userId = new("77029e96-0fdd-4e82-b894-7241ea4113fd");
		private readonly DateTime _dateTime = DateTime.UtcNow;
		private const string JwtSecret = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkFkbWluIiwiaWF0IjoxNjM3MTc2NTE5fQ.ESzN9FfHmOT2BDHyp6WSfcVs4PdFFfGiUobj_wNXWtE";
		private const string JwtAudience = "education";
		private const string IpAddress = "127.0.0.1";
		private const string UserName = "userName";
		private const string PassWord = "passWord";

		private Mock<IGrpcServiceProxy<IUserInfoService>> _userInfoService;
		private IEncoderDecoder _encoderDecoder;
		private Mock<ILogger<TokenService>> _logger;
		private Mock<ISystemClock> _systemClock;

		private TokenService _sut;

		[SetUp]
		public void Setup()
		{
			_userInfoService = new Mock<IGrpcServiceProxy<IUserInfoService>>();
			_encoderDecoder = new EncoderDecoder("key");
			_logger = new Mock<ILogger<TokenService>>();
			_systemClock = new Mock<ISystemClock>();

			_systemClock
				.Setup(clock => clock.Now)
				.Returns(_dateTime);

			_sut = new TokenService(
				_userInfoService.Object,
				_encoderDecoder,
				_logger.Object,
				_systemClock.Object,
				JwtAudience, JwtSecret, 10, 20);
		}

		[Test]
		public async Task GenerateTokensAsync_return_token_info()
		{
			_userInfoService
				.Setup(proxy => proxy.Service.GetUserInfoForAuth(It.Is<UserInfoAuthRequest>(request =>
					request.UserName == UserName && request.Password == PassWord)))
				.Returns(ValueTask.FromResult(new UserInfoForAuthRespose
				{
					UserInfo = new UserInfoGrpcModel
					{
						UserId = _userId,
						Role = UserRole.Default
					}
				}));

			AuthTokenInfo tokenInfo = await _sut.GenerateTokensAsync(UserName, IpAddress, PassWord);

			AssertTokenInfo(tokenInfo.Token, tokenInfo.RefreshToken);
		}

		[Test]
		public async Task GenerateTokensAsync_return_flag_if_user_info_not_found()
		{
			_userInfoService
				.Setup(proxy => proxy.Service.GetUserInfoForAuth(It.Is<UserInfoAuthRequest>(request =>
					request.UserName == UserName && request.Password == PassWord)))
				.Returns(ValueTask.FromResult<UserInfoForAuthRespose>(null));

			AuthTokenInfo tokenInfo = await _sut.GenerateTokensAsync(UserName, IpAddress, PassWord);

			Assert.IsNotNull(tokenInfo);
			Assert.IsTrue(tokenInfo.UserNotFound);
		}

		[Test]
		public async Task GenerateTokensAsync_return_flag_if_user_not_found()
		{
			_userInfoService
				.Setup(proxy => proxy.Service.GetUserInfoForAuth(It.Is<UserInfoAuthRequest>(request =>
					request.UserName == UserName && request.Password == PassWord)))
				.Returns(ValueTask.FromResult(new UserInfoForAuthRespose
				{
					UserNotFound = true
				}));

			AuthTokenInfo tokenInfo = await _sut.GenerateTokensAsync(UserName, IpAddress, PassWord);

			Assert.IsNotNull(tokenInfo);
			Assert.IsTrue(tokenInfo.UserNotFound);
		}

		[Test]
		public async Task GenerateTokensAsync_return_flag_if_user_passsword_not_valid()
		{
			_userInfoService
				.Setup(proxy => proxy.Service.GetUserInfoForAuth(It.Is<UserInfoAuthRequest>(request =>
					request.UserName == UserName && request.Password == PassWord)))
				.Returns(ValueTask.FromResult(new UserInfoForAuthRespose
				{
					InvalidPassword = true
				}));

			AuthTokenInfo tokenInfo = await _sut.GenerateTokensAsync(UserName, IpAddress, PassWord);

			Assert.IsNotNull(tokenInfo);
			Assert.IsTrue(tokenInfo.InvalidPassword);
		}

		[Test]
		public async Task RefreshTokensAsync_return_token_info()
		{
			_userInfoService
				.Setup(proxy => proxy.Service.GetUserInfoByIdAsync(It.Is<UserInfoRequest>(request => request.UserId == _userId)))
				.Returns(ValueTask.FromResult(new UserInfoResponse
				{
					UserInfo = new UserInfoGrpcModel
					{
						UserId = _userId,
						Role = UserRole.Default
					}
				}));

			string currentRefreshToken = GenerateRefreshToken(_dateTime);

			TokenInfo tokenInfo = await _sut.RefreshTokensAsync(currentRefreshToken, IpAddress);

			AssertTokenInfo(tokenInfo.Token, tokenInfo.RefreshToken);
		}

		[Test]
		public async Task RefreshTokensAsync_return_null_if_current_refresh_token_is_invalid()
		{
			TokenInfo tokenInfo = await _sut.RefreshTokensAsync("123", IpAddress);

			Assert.IsNull(tokenInfo);
		}

		[Test]
		public async Task RefreshTokensAsync_return_null_if_current_refresh_token_is_expired()
		{
			string currentRefreshToken = GenerateRefreshToken(_dateTime.AddDays(-1));

			TokenInfo tokenInfo = await _sut.RefreshTokensAsync(currentRefreshToken, IpAddress);

			Assert.IsNull(tokenInfo);
		}

		[Test]
		public async Task RefreshTokensAsync_return_null_if_current_refresh_token_created_from_another_ip()
		{
			string currentRefreshToken = GenerateRefreshToken(_dateTime);

			TokenInfo tokenInfo = await _sut.RefreshTokensAsync(currentRefreshToken, "127.0.0.2");

			Assert.IsNull(tokenInfo);
		}

		private void AssertTokenInfo(string jwtToken, string refreshToken)
		{
			Assert.IsNotNull(refreshToken);

			var refreshTokenInfo = _encoderDecoder.DecodeProto<RefreshTokenInfo>(refreshToken);
			Assert.IsNotNull(refreshTokenInfo);
			Assert.AreEqual(20, refreshTokenInfo.RefreshTokenExpires.Subtract(_dateTime).Minutes);
			Assert.AreEqual(IpAddress, refreshTokenInfo.RefreshTokenIpAddress);
			Assert.AreEqual(_userId, refreshTokenInfo.RefreshTokenUserId);

			Assert.IsNotNull(jwtToken);

			JwtSecurityToken token = new JwtSecurityTokenHandler().ReadJwtToken(jwtToken);
			Assert.AreEqual(_userId.ToString(), token.Claims.First(claim => claim.Type == "unique_name").Value);
			Assert.AreEqual(UserRole.Default, token.Claims.First(claim => claim.Type == "role").Value);
		}

		private string GenerateRefreshToken(DateTime expireDate, string ip = IpAddress) => _encoderDecoder.EncodeProto(new RefreshTokenInfo
		{
			RefreshTokenUserId = _userId,
			RefreshTokenIpAddress = ip,
			RefreshTokenExpires = expireDate
		});
	}
}