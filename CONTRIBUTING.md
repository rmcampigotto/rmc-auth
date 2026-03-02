# Contributing to RMC-AUTH

Thank you for considering contributing to RMC-AUTH. This document explains how to run the project locally and how to propose changes.

## Prerequisites

- **Node.js** 18 or later (20 LTS recommended)
- **npm** 9 or later

## Development setup

1. Clone the repository:
   ```bash
   git clone https://github.com/rmcampigotto/rmc-auth.git
   cd rmc-auth
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run tests:
   ```bash
   npm test
   ```

4. Build the library:
   ```bash
   npm run build
   ```

## Scripts

| Script          | Description                    |
|-----------------|--------------------------------|
| `npm test`      | Run the test suite             |
| `npm run test:watch` | Run tests in watch mode  |
| `npm run test:cov`   | Run tests with coverage |
| `npm run build`      | Build the library (tsup)  |

## Proposing changes

1. Open an issue to discuss the change (optional but recommended for larger changes).
2. Fork the repo and create a branch from `main` (or `master`).
3. Make your changes; keep the test suite passing and add tests for new behavior when relevant.
4. Run `npm test` and `npm run build` before submitting.
5. Open a Pull Request with a clear description and reference to any related issue.

## Code style

- Use TypeScript with strict mode.
- Follow the existing style (formatting, naming). Consistency with the current codebase is preferred.
- Prefer clear naming and small, focused functions.

## Commit messages

- Use clear, descriptive messages.
- Optional: follow [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat: add X`, `fix: Y`) to help with changelog generation.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
