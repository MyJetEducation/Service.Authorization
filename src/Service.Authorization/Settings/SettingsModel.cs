using MyJetWallet.Sdk.Service;
using MyYamlParser;

namespace Service.Authorization.Settings
{
    public class SettingsModel
    {
        [YamlProperty("Authorization.SeqServiceUrl")]
        public string SeqServiceUrl { get; set; }

        [YamlProperty("Authorization.ZipkinUrl")]
        public string ZipkinUrl { get; set; }

        [YamlProperty("Authorization.ElkLogs")]
        public LogElkSettings ElkLogs { get; set; }
    }
}
