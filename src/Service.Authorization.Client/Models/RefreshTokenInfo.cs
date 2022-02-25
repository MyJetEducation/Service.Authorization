using System;
using System.Runtime.Serialization;

namespace Service.Authorization.Client.Models
{
	[DataContract]
	public class RefreshTokenInfo
	{
		[DataMember(Order = 1)]
		public Guid? RefreshTokenUserId { get; set; }

		[DataMember(Order = 2)]
		public DateTime RefreshTokenExpires { get; set; }

		[DataMember(Order = 3)]
		public string RefreshTokenIpAddress { get; set; }
	}
}