import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";
import type { EncryptionOptions } from "../../interfaces/encryption.options";

@Injectable()
export class EncryptionOptionsValidator implements OnModuleInit {
  constructor(@Inject(MODULE_OPTIONS_TOKEN) private readonly options: EncryptionOptions) {}

  onModuleInit(): void {
    const algorithm = this.options.algorithm ?? "bcrypt";
    if (algorithm === "bcrypt") {
      const rounds = this.options.saltRounds ?? 10;
      if (typeof rounds !== "number" || rounds < 1 || rounds > 31) {
        throw new Error(
          "EncryptionModule: 'saltRounds' must be a number between 1 and 31 when using bcrypt."
        );
      }
    }
  }
}
