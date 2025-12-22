import { ConfigurableModuleBuilder } from "@nestjs/common";
import { AuthOptions } from "../../interfaces/auth.options";

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
  new ConfigurableModuleBuilder<AuthOptions>()
    .setClassMethodName('register')
    .build();