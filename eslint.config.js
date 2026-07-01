// Flat ESLint config. Type-aware linting via typescript-eslint for the whole
// library, with the unsafe-any / promise rules relaxed in tests and the demo,
// which deliberately poke at untyped JSON fixtures and DOM event handlers.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "dist-demo/**",
      "src/wasm/**",
      "vendor/**",
      "node_modules/**",
      "**/fixtures/**",
      "scripts/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  // The ESLint config file itself is plain JS — no type information available.
  {
    files: ["**/*.js"],
    extends: [tseslint.configs.disableTypeChecked],
  },
  // Library source: hold it to the stricter bar.
  {
    files: ["src/**/*.ts"],
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/explicit-module-boundary-types": "error",
    },
  },
  // Tests and the browser demo cross untyped boundaries (JSON fixtures, the
  // DOM, the mock server's request bodies); the unsafe-any family and the
  // promise rules add only noise there.
  {
    files: ["test/**/*.ts", "demo/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-floating-promises": "off",
      "@typescript-eslint/no-misused-promises": "off",
    },
  },
  prettier,
);
