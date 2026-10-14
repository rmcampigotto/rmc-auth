import { ConfigurableModuleBuilder } from "@nestjs/common";
import { EncryptionOptions } from "../../interfaces/encryption.options";

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } =
  new ConfigurableModuleBuilder<EncryptionOptions>()
    .setClassMethodName('register')
    .setExtras({ isGlobal: false }, (definition, extras) => ({
      ...definition,
      global: extras.isGlobal,
    }))
    .build();
