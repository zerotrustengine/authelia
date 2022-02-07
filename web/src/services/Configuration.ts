import { Configuration } from "@models/Configuration";
import { ConfigurationPath } from "@services/Api";
import { Get } from "@services/Client";
import { toEnum, Method2FA } from "@services/UserInfo";

interface ConfigurationPayload {
    available_methods: Method2FA[];
    second_factor_enabled: boolean;
    default_2fa_method: Method2FA;
}

export async function getConfiguration(): Promise<Configuration> {
    const config = await Get<ConfigurationPayload>(ConfigurationPath);
    return {
        ...config,
        available_methods: new Set(config.available_methods.map(toEnum)),
        default_2fa_method: toEnum(config.default_2fa_method),
    };
}
