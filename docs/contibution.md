## Contributions

### Validating index.d.ts type definitions
For validation it helps to generate and compare the types to the generated files using:
```sh
npx typescript index.js --declaration --allowJs --emitDeclarationOnly --outDir types
```
