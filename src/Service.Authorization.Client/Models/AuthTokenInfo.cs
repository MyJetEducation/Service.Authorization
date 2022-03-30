namespace Service.Authorization.Client.Models
{
	public class AuthTokenInfo: TokenInfo
	{
		public bool UserNotFound { get; set; }

		public bool InvalidPassword { get; set; }

		public bool IsValid() => !UserNotFound && !InvalidPassword;
	}
}