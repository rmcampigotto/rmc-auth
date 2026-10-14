import { ConfigurableModuleBuilder } from "@nestjs/common";
import { AuthOptions } from "../../interfaces/auth.options";

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } =
  new ConfigurableModuleBuilder<AuthOptions>()
    .setClassMethodName('register')
    .setExtras({ isGlobal: true }, (definition, extras) => ({
      ...definition,
      global: extras.isGlobal,
    }))
    .build();
