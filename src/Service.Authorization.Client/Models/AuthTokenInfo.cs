namespace Service.Authorization.Client.Models
{
	public class AuthTokenInfo
	{
		public string Token { get; set; }

		public string RefreshToken { get; set; }

		public bool UserNotFound { get; set; }

		public bool InvalidPassword { get; set; }

		public bool IsValid() => !UserNotFound && !InvalidPassword;
	}
}