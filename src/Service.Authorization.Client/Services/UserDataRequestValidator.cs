using System.Text.RegularExpressions;
using Service.Core.Client.Extensions;

namespace Service.Authorization.Client.Services
{
	public class UserDataRequestValidator
	{
		private static readonly Regex PasswordRegex = new(@"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d\W_]{8,31}$",
			RegexOptions.Compiled);

		private static readonly Regex FullNameRegex = new("^([A-Za-z]+)\\ ([A-Za-z]+)$",
			RegexOptions.Compiled);

		private static readonly Regex EmailRegex = new(@"^([0-9a-zA-Z]([\+\-_\.][0-9a-zA-Z]+)*)+@(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]*\.)+[a-zA-Z0-9]{2,17})$",
			RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.IgnoreCase);

		public static bool ValidatePassword(string value) => !value.IsNullOrWhiteSpace() && PasswordRegex.IsMatch(value);

		public static bool ValidateLogin(string value) => !value.IsNullOrWhiteSpace() && EmailRegex.IsMatch(value);

		public static bool ValidateFullName(string value) => !value.IsNullOrWhiteSpace() && FullNameRegex.IsMatch(value);
	}
}