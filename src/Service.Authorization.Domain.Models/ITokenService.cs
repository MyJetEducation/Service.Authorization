using System.Threading.Tasks;

namespace Service.Authorization.Domain.Models
{
	public interface ITokenService
	{
		ValueTask<TokenInfo> GenerateTokensAsync(string userName, string ipAddress, string password = null);

		ValueTask<TokenInfo> RefreshTokensAsync(string currentRefreshToken, string ipAddress);
	}
}