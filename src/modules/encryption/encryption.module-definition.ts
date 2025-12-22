import { ConfigurableModuleBuilder } from "@nestjs/common";
import { EncryptionOptions } from "../../interfaces/encryption.options";

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
  new ConfigurableModuleBuilder<EncryptionOptions>()
    .setClassMethodName('register')
    .build();