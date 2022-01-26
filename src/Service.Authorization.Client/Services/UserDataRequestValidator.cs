using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Service.Authorization.Client.Services
{
	public class UserDataRequestValidator
	{
		private static readonly Regex PasswordRegex = new Regex("^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,31}$", RegexOptions.Compiled);
		private static readonly Regex FullNameRegex = new Regex("^([A-Za-z]+)\\ ([A-Za-z]+)$", RegexOptions.Compiled);

		public static bool ValidatePassword(string value) => PasswordRegex.IsMatch(value);

		public static bool ValidateLogin(string value) => new EmailAddressAttribute().IsValid(value);

		public static bool ValidateFullName(string value) => FullNameRegex.IsMatch(value);
	}
}