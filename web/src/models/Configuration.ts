import { SecondFactorMethod } from "@models/Methods";

export interface Configuration {
    available_methods: Set<SecondFactorMethod>;
    second_factor_enabled: boolean;
    default_2fa_method?: SecondFactorMethod;
}
