declare module "owasp-password-strength-test" {
  interface OwaspTestResult {
    errors: string[];
    failedTests: number[];
    requiredTestErrors: string[];
    optionalTestErrors: string[];
    passedTests: number[];
    isPassphrase: boolean;
    strong: boolean;
    optionalTestsPassed: number;
  }

  interface OwaspPasswordStrengthTest {
    test(password: string): OwaspTestResult;
  }

  const owasp: OwaspPasswordStrengthTest;

  export default owasp;
}

