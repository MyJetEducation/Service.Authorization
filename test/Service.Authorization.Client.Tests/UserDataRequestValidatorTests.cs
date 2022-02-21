using NUnit.Framework;
using Service.Authorization.Client.Services;

namespace Service.Authorization.Client.Tests
{
	public class UserDataRequestValidatorTests
	{
		[TestCase("abc@mail.com")]
		[TestCase("abc@ma-il.com")]
		[TestCase("abc1@mail2.cc")]
		[TestCase("abc-d@mail.com")]
		[TestCase("abc.def@mail.com")]
		[TestCase("abc_def@mail.com")]
		[TestCase("l@d.ru")]
		[TestCase("ma@hostname.com")]
		[TestCase("ma@hostname.comcom")]
		[TestCase("MA@hostname.coMCom")]
		[TestCase("m.a@hostname.co")]
		[TestCase("m_a1a@hostname.com")]
		[TestCase("ma-a@hostname.com")]
		[TestCase("ma-a@hostname.com.edu")]
		[TestCase("ma-a.aa@hostname.com.edu")]
		[TestCase("ma.h.saraf.onemore@hostname.com.edu")]
		[TestCase("ma12@hostname.com")]
		[TestCase("12@hostname.com")]
		public void ValidateLogin_return_true_if_email_is_valid(string mail)
		{
			bool isValid = UserDataRequestValidator.ValidateLogin(mail);

			Assert.IsTrue(isValid);
		}

		[TestCase(null)]
		[TestCase("")]
		[TestCase("abc")]
		[TestCase("abc@")]
		[TestCase("@mail.com")]
		[TestCase("[a]bc@mail.com")]
		[TestCase("a[b]c@mail.com")]
		[TestCase("abc@m[a]il.com")]
		[TestCase("abc@mail")]
		[TestCase("abc-@mail.com")]
		[TestCase("abc..def@mail.com")]
		[TestCase(".abc@mail.com")]
		[TestCase("abc#def@mail.com")]
		[TestCase("abc.def@mail.c")]
		[TestCase("abc.def@mail#archive.com")]
		[TestCase("abc.def@mail")]
		[TestCase("abc.def@mail..com")]
		[TestCase("l@d.c")]
		[TestCase("Abc.example.com")]
		[TestCase("A@b@c@example.com")]
		[TestCase("ma...ma@jjf.co")]
		[TestCase("ma@@jjf.com")]
		[TestCase("ma.@jjf.com")]
		[TestCase("ma_@jjf.com")]
		[TestCase("ma_@jjf")]
		[TestCase("ma_@jjf.")]
		[TestCase("ma@jjf.")]
		public void ValidateLogin_return_false_if_email_is_not_valid(string mail)
		{
			bool isValid = UserDataRequestValidator.ValidateLogin(mail);

			Assert.IsFalse(isValid);
		}

		[TestCase("qwertyu1")]
		[TestCase("a234567890a234567890a234567890b")]
		[TestCase("Awertyu1")]
		[TestCase("1234567a")]
		[TestCase("1!234567a")]
		[TestCase("12.34567a")]
		[TestCase("123~!@#$%^&*-+;`=|\\b")]
		[TestCase("(){}[]:\",'<>_.?/|4567a")]
		[TestCase("123-45 67a")]
		[TestCase("123-4567#a")]
		[TestCase("123-4567#a.")]
		[TestCase("!@#q2cd1")]
		public void ValidatePassword_return_true_if_password_is_valid(string mail)
		{
			bool isValid = UserDataRequestValidator.ValidatePassword(mail);

			Assert.IsTrue(isValid);
		}

		[TestCase(null)]
		[TestCase("")]
		[TestCase("qwerty1")]
		[TestCase("a234567890a234567890a234567890b1")]
		[TestCase("qwertyui")]
		[TestCase("12345678")]
		[TestCase("Юqwertyu1")]
		public void ValidatePassword_return_false_if_password_is_not_valid(string mail)
		{
			bool isValid = UserDataRequestValidator.ValidatePassword(mail);

			Assert.IsFalse(isValid);
		}

		[TestCase("John")]
		[TestCase("Smith")]
		[TestCase("D'Largy")]
		[TestCase("Doe-Smith")]
		[TestCase("Doe Smith")]
		[TestCase("Sausage-Hausen")]
		[TestCase("d'Arras")]
		[TestCase("SMITH")]
		[TestCase("STeve")]
		[TestCase("d'Are")]
		[TestCase("Wu")]
		[TestCase("O'Neal")]
		[TestCase("Johnson-Smith")]
		[TestCase("O Henry")]
		[TestCase("McCarty")]
		[TestCase("B-Ball")]
		[TestCase("el Jeffe")]
		[TestCase("Björk")]
		[TestCase("King, Jr.")]
		public void ValidateName_return_true_if_name_is_valid(string name)
		{
			bool isValid = UserDataRequestValidator.ValidateName(name);

			Assert.IsTrue(isValid);
		}

		[TestCase(null)]
		[TestCase("'")]
		[TestCase("-")]
		[TestCase(" ")]
		[TestCase(",")]
		[TestCase(".")]
		[TestCase("1")]
		[TestCase("2")]
		[TestCase("John#")]
		[TestCase("John!")]
		[TestCase("John@")]
		[TestCase("John$")]
		[TestCase("John%")]
		[TestCase("John/")]
		[TestCase("John^")]
		[TestCase("King&")]
		[TestCase("King*")]
		[TestCase("King)")]
		[TestCase("King[")]
		[TestCase("King{")]
		[TestCase("King=")]
		[TestCase("King|")]
		[TestCase("King1")]
		[TestCase("King234")]
		[TestCase("King/")]
		[TestCase("King>")]
		[TestCase("King?")]
		[TestCase("King;")]
		[TestCase("King:")]
		[TestCase("King:~")]
		public void ValidateName_return_false_if_name_is_not_valid(string name)
		{
			bool isValid = UserDataRequestValidator.ValidateName(name);

			Assert.IsFalse(isValid);
		}
	}
}