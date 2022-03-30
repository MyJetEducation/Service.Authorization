using System.Threading.Tasks;
using Service.Authorization.Client.Models;

namespace Service.Authorization.Client.Services
{
	public interface ITokenService
	{
		ValueTask<AuthTokenInfo> GenerateTokensAsync(string userName, string ipAddress, string password = null);

		ValueTask<TokenInfo> RefreshTokensAsync(string currentRefreshToken, string ipAddress);
	}
}