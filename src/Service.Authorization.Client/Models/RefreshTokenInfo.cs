using System;

namespace Service.Authorization.Client.Models
{
	public class RefreshTokenInfo
	{
		public Guid? RefreshTokenUserId { get; set; }

		public DateTime RefreshTokenExpires { get; set; }
		
		public string RefreshTokenIpAddress { get; set; }
	}
}