import { Module } from "@nestjs/common";
import { EncryptionService } from "./encryption.service";
import { ConfigurableModuleClass } from "./encryption.module-definition";

@Module({
  providers: [EncryptionService],
  exports: [EncryptionService],
})
export class EncryptionModule extends ConfigurableModuleClass {};