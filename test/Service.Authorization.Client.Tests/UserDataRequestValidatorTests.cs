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
		public void ValidateLoginReturn_true_if_email_is_valid(string mail)
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
		public void ValidateLoginReturn_false_if_email_is_not_valid(string mail)
		{
			bool isValid = UserDataRequestValidator.ValidateLogin(mail);

			Assert.IsFalse(isValid);
		}
	}
}