using System.Text.RegularExpressions;
using Service.Core.Client.Extensions;

namespace Service.Authorization.Client.Services
{
	public static class UserDataRequestValidator
	{
		private static readonly Regex PasswordRegex = new(@"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d\W_]{8,31}$",
			RegexOptions.Compiled);

		private static readonly Regex NameRegex = new(@"^[\w\s',.\-].[^+#!@$%\/^&*()[\]{}=|\<>?;:\d]*$",
			RegexOptions.Compiled);

		private static readonly Regex EmailRegex = new(@"^([0-9a-zA-Z]([\+\-_\.][0-9a-zA-Z]+)*)+@(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]*\.)+[a-zA-Z0-9]{2,17})$",
			RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.IgnoreCase);

		public static bool ValidatePassword(string value) => !value.IsNullOrWhiteSpace() && PasswordRegex.IsMatch(value);

		public static bool ValidateLogin(string value) => !value.IsNullOrWhiteSpace() && EmailRegex.IsMatch(value);

		public static bool ValidateName(string value) => !value.IsNullOrWhiteSpace() && NameRegex.IsMatch(value);
	}
}