import { Module } from "@nestjs/common";
import { EncryptionService } from "./encryption.service";
import { EncryptionOptionsValidator } from "./encryption-options.validator";
import { ConfigurableModuleClass } from "./encryption.module-definition";

@Module({
  providers: [EncryptionOptionsValidator, EncryptionService],
  exports: [EncryptionService],
})
export class EncryptionModule extends ConfigurableModuleClass {}