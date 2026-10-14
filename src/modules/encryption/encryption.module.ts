import { Module } from "@nestjs/common";
import { EncryptionService } from "./encryption.service";
import { EncryptionOptionsValidator } from "./encryption-options.validator";
import { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";

@Module({
  providers: [EncryptionOptionsValidator, EncryptionService],
  exports: [EncryptionService, MODULE_OPTIONS_TOKEN],
})
export class EncryptionModule extends ConfigurableModuleClass {}
