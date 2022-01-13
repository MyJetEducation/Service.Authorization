using JetBrains.Annotations;
using MyJetWallet.Sdk.Grpc;

namespace Service.Authorization.Client
{
	[UsedImplicitly]
	public class AuthorizationClientFactory : MyGrpcClientFactory
	{
		public AuthorizationClientFactory(string grpcServiceUrl) : base(grpcServiceUrl)
		{
		}
	}
}